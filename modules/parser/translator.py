from pathlib import Path
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from typing import Dict, Any, Optional, List
import yaml

# atomic rule = one rule --> one search
#correlation rule = conting results of ther rules

MAX_CLAUSES = 500
DEFAULT_PIPELINE_PATH = Path(__file__).resolve().parent.parent / "pipelines" / "opensearch_custom.yml"

#loads and returns ECS (Elastic Common Schema) Processing Pipeline from the YAML configuration
#this pipeline translates standard Sigma field names to ECS field names and prefixes unmapped fields with winlog.event_data."something"
def get_elastic_pipeline(pipeline_path: str | Path = DEFAULT_PIPELINE_PATH) -> ProcessingPipeline:
    path = Path(pipeline_path)
    if not path.is_file():
        raise FileNotFoundError(f"Pipeline file not found: {path}")
    return ProcessingPipeline.from_yaml(path.read_text(encoding="utf-8"))

pipeline = get_elastic_pipeline()
BACKEND_ECS = OpensearchLuceneBackend(processing_pipeline=pipeline)
BACKEND_NATIVE = OpensearchLuceneBackend()

def load_field_mapping(path: str | Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    file_path = Path(path)

    if not file_path.is_file():
        return mapping

    raw_text = file_path.read_text(encoding="utf-8")
    parsed_yaml = yaml.safe_load(raw_text)

    transformations = parsed_yaml.get("transformations", [])
    for i in range(len(transformations)):
        t = transformations[i]
        if t.get("type") == "field_name_mapping":
            field_dict = t.get("mapping", {})
            for k, v in field_dict.items():
                mapping[k] = v

    return mapping

FIELD_MAPPING: Dict[str, Any] = load_field_mapping(DEFAULT_PIPELINE_PATH)

#return the FIELD_MAPPING name if found, otherwise the name unchanged
def map_field(field_name: str, schema: str = "native") -> str:
    if schema == "native":
        return field_name
    if field_name in FIELD_MAPPING:
        return FIELD_MAPPING[field_name]
    return field_name

def translate_atomic_rule(rule: SigmaRule, timeframe: str = "now-15m", size: int = 500, schema: str = "native") -> Optional[Dict[str, Any]]:
    #step 1 -- generate Lucene query strings from Sigma AST
    backend = BACKEND_NATIVE if schema == "native" else BACKEND_ECS

    try:
        query_strings: List[str] = backend.convert_rule(rule)
    except Exception:
        query_strings = None
        
    if not query_strings:
        return None

    #step 2 -- if a rule produces several queries, they are wrapped in parentheses and joined with OR
    if len(query_strings) == 1:
        full_query = query_strings[0]
    else:
        parts: List[str] = []
        for i in range(len(query_strings)): #bp
            parts.append("(" + query_strings[i] + ")")
        #check the number of generated query parts against a maximum allowed clauses
        if len(parts) <= MAX_CLAUSES:
            full_query = " OR ".join(parts)
        else:
            print(f"{rule.title} is exceeding the number of maximum clauses")
            return None
        
    # guard against massive Lucene queries whose wildcard expansion exceeds Lucene's 10240 nested clause limit
    if len(full_query) > 25000:
        print(f"{rule.title} skipped: query length ({len(full_query)} chars) exceeds safe Lucene clause limit")
        return None

    #step 3 -- build filters list
    filters: List[Dict[str, Any]] = [
        {
            "query_string": {
                "query": full_query,
                "analyze_wildcard": True,
                "default_operator": "AND"
            }
        }
    ]

    if timeframe and timeframe.lower() != "all":
        filters.append({
            "range": {
                "@timestamp": {
                    "gte": timeframe,
                    "lte": "now"
                }
            }
        })

    #step 4 -- construct opensearch Query DSL
    query_body: Dict[str, Any] = {
        "size": size,
        "query": {
            "bool": {
                "filter": filters
            }
        }
    }

    return query_body

def translate_correlation_rule(corr_rule: SigmaCorrelationRule, ref_query: Optional[str] = None, timeframe: Optional[str] = None, schema: str = "native") -> Dict[str, Any]:
    # step 1 -- Determine timeframe
    #timespan: 5m
    if timeframe and timeframe.lower() == "all":
        tf = None
    elif timeframe:
        tf = timeframe
    elif corr_rule.timespan and corr_rule.timespan.spec:
        tf = "now-" + str(corr_rule.timespan.spec)
    else:
        tf = "now-5m"

    # step 2 -- Determine threshold count
    '''
    condition:
        gte: 5
    '''
    min_count = 1
    if corr_rule.condition and corr_rule.condition.count is not None:
        min_count = int(corr_rule.condition.count)

    # step 3 -- Build filter list imperatively
    filters: List[Dict[str, Any]] = []

    #reference query like in the rule you might have: rule: -failed_login and for that youwill need a query
    if ref_query:
        filters.append({
            "query_string": {
                    "query": ref_query,
                    "analyze_wildcard": True,
                    "default_operator": "AND"
            }
        })

    # add time range filter unless all
    if tf and tf.lower() != "all":
        filters.append({
            "range": {
                "@timestamp": {
                    "gte": tf,
                    "lte": "now"
                }
            }
        })

    # step 4 -- Build group-by terms imperatively
    '''
    group-by:
        - TargetUserName
        - Hostname
    '''
    terms_list: List[Dict[str, str]] = []
    if corr_rule.group_by:
        for raw_field in corr_rule.group_by:
            mapped = map_field(raw_field, schema=schema)
            if not mapped.endswith(".keyword") and not mapped.endswith(".id"):
                final_field = mapped + ".keyword"
            else:
                final_field = mapped
            terms_list.append({"field": final_field})

    # step 5 -- Construct OpenSearch Query DSL with aggregation
    
    #only one element in group-by
    if len(terms_list) == 1:
            aggs_body = {
                "terms": {
                    "field": terms_list[0]["field"],
                    "size": 1000,
                    "min_doc_count": min_count
                }
            }
    elif len(terms_list) > 1:
        aggs_body = {
            "multi_terms": {
                "terms": terms_list,
                "min_doc_count": min_count
            }
        }
    else:
        #without group-by
        aggs_body = {
            "value_count": {
                "field": "_id"
            }
        }

    query_body: Dict[str, Any] = {
        "size": 0,
        "query": {
            "bool": {
                "filter": filters
            }
        },
        "aggs": {
            "correlation_buckets": aggs_body
        }
    }
    return query_body