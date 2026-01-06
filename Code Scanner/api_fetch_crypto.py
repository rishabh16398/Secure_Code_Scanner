import json, os, logging, re, hashlib, hmac, binascii
from decimal import Decimal, ROUND_HALF_UP
import pg8000.native
from datetime import datetime, date, time, timezone, timedelta
from zoneinfo import ZoneInfo
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#testing code for deployment
DB_HOST = os.environ.get('DB_HOST')
DB_PORT = int(os.environ.get('DB_PORT', 5432))
DB_NAME = os.environ.get('DB_NAME')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASS')
SCHEMA = os.getenv("DB_SCHEMA", "ve")

STRICT_FX = os.getenv("STRICT_FX","false").lower() in ("1","true","yes")
CONVERT_IF_MISSING = os.getenv("CONVERT_IF_MISSING","false").lower() in ("1","true","yes")
SHOW_CUTOFF = os.getenv("SHOW_CUTOFF","false").lower() in ("1","true","yes")

RAW_TICKS_TABLE = os.getenv("RAW_TICKS_TABLE","raw_price_ticks")
RAW_COL_SOURCE_ID = os.getenv("RAW_COL_SOURCE_ID","source_id")
RAW_COL_PRICE = os.getenv("RAW_COL_PRICE","provider_price")
RAW_COL_VOLUME = os.getenv("RAW_COL_VOLUME","volume_24h")
RAW_COL_RUN_ID = os.getenv("RAW_COL_RUN_ID","run_id")
RAW_COL_ASSET_ID = os.getenv("RAW_COL_ASSET_ID","asset_id")
RAW_COL_FIAT = os.getenv("RAW_COL_FIAT","quote_fiat")

DATA_SOURCES_SCHEMA = os.getenv("DATA_SOURCES_SCHEMA",SCHEMA)
DATA_SOURCES_TABLE = os.getenv("DATA_SOURCES_TABLE","data_sources")
DATA_SOURCES_COL_ID = os.getenv("DATA_SOURCES_COL_ID","id")
DATA_SOURCES_COL_NAME = os.getenv("DATA_SOURCES_COL_NAME","name")

# DynamoDB configuration
DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_API_KEYS_TABLE", "APIKey").strip()
dynamodb = boto3.client("dynamodb")

# =========================================================
# HELPERS (ALL ORIGINAL FUNCTIONS INCLUDED)
# =========================================================

def decimal_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def parse_target_timestamp(s,eod_tz=None):
    s=(s or "").strip()
    if not s: raise ValueError("date is empty")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}",s):
        d=date.fromisoformat(s)
        tzinfo=eod_tz or timezone.utc
        eod_local=datetime.combine(d,time(23,59,59,999999),tzinfo=tzinfo)
        return eod_local.astimezone(timezone.utc)
    s2=s.replace('Z','+00:00')
    dt=datetime.fromisoformat(s2)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def parse_range(a,b):
    if not a or not b: raise ValueError("Both start and end are required")
    a=a.strip(); b=b.strip()
    try:
        sdt=datetime.fromisoformat(a.replace('Z','+00:00'))
        sdt=sdt.astimezone(timezone.utc) if sdt.tzinfo else sdt.replace(tzinfo=timezone.utc)
    except:
        d=date.fromisoformat(a)
        sdt=datetime.combine(d,time(0,0,0),tzinfo=timezone.utc)
    try:
        edt=datetime.fromisoformat(b.replace('Z','+00:00'))
        edt=edt.astimezone(timezone.utc) if edt.tzinfo else edt.replace(tzinfo=timezone.utc)
    except:
        d=date.fromisoformat(b)
        edt=datetime.combine(d,time(23,59,59,999999),tzinfo=timezone.utc)
    if sdt>edt: raise ValueError("start must be <= end")
    return sdt,edt

def _parse_assets(event):
    mv=event.get('multiValueQueryStringParameters') or {}
    if 'asset' in mv and mv['asset']:
        assets=mv['asset']
    else:
        params=event.get('queryStringParameters') or {}
        raw=(params.get('asset') or '').strip()
        if not raw: return []
        if raw.startswith("[") and raw.endswith("]"): raw=raw[1:-1]
        assets=[p for p in (s.strip() for s in raw.split(",")) if p]
    seen=set(); out=[]
    for s in assets:
        u=s.upper()
        if u and u not in seen:
            seen.add(u); out.append(u)
    return out

def _parse_tz_offset(tz):
    tz=tz.strip()
    sign=1 if tz[0]=="+" else -1
    return timezone(sign*timedelta(hours=int(tz[1:3]),minutes=int(tz[4:6])))

def _local_day_bounds(d, tz):
    d=date.fromisoformat(d.strip())
    off=_parse_tz_offset(tz)
    start=datetime.combine(d,time(0,0,0),tzinfo=off)
    end=datetime.combine(d,time(23,59,59,999999),tzinfo=off)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)

def _parse_any_tz(s):
    if not s: return timezone.utc
    s=s.strip(); u=s.upper()
    if u in ("UTC","Z"): return timezone.utc
    abbrev={"AEST":"Australia/Brisbane","AEDT":"Australia/Sydney",
            "ACST":"Australia/Darwin","ACDT":"Australia/Adelaide",
            "AWST":"Australia/Perth"}
    if u in abbrev: return ZoneInfo(abbrev[u])
    if len(u)>=6 and u[0] in "+-" and u[1:3].isdigit() and u[3]==":" and u[4:6].isdigit():
        return _parse_tz_offset(u)
    try: return ZoneInfo(s)
    except: raise ValueError("Invalid out_tz")

def _get_bucket_sql(i):
    return {"1m":"date_trunc('minute', vv.valuation_ts)",
            "5m":"to_timestamp(floor(extract(epoch from vv.valuation_ts)/300)*300)",
            "15m":"to_timestamp(floor(extract(epoch from vv.valuation_ts)/900)*900)",
            "1h":"date_trunc('hour', vv.valuation_ts)",
            "1d":"date_trunc('day', vv.valuation_ts)"}.get(i)

def _table_exists(conn,sch,tbl):
    try:
        r=conn.run("""SELECT 1 FROM information_schema.tables 
                      WHERE table_schema=:s AND table_name=:t LIMIT 1""",
                   s=sch,t=tbl)
        return bool(r)
    except:
        return False

def _fetch_fx(conn,ccy):
    cc=(ccy or "USD").upper().strip()
    if cc=="USD": return 1.0,"USD"
    def fxapi(a,b):
        try:
            r=conn.run(f"""SELECT best_rate FROM {SCHEMA}.fx_api
                           WHERE base_ccy=:a AND target_ccy=:b
                           ORDER BY decided_at DESC NULLS LAST, as_of_unix DESC NULLS LAST, id DESC NULLS LAST
                           LIMIT 1""",a=a,b=b)
            if r and r[0][0] is not None: return float(r[0][0])
        except: pass
    def raw(a,b):
        try:
            r=conn.run(f"""SELECT quote_rate FROM {SCHEMA}.raw_fx_api
                           WHERE base_ccy=:a AND target_ccy=:b
                           ORDER BY inserted_at DESC NULLS LAST, id DESC NULLS LAST
                           LIMIT 1""",a=a,b=b)
            if r and r[0][0] is not None: return float(r[0][0])
        except: pass
    direct=fxapi("USD",cc) or raw("USD",cc)
    if direct: return direct,cc
    inv=fxapi(cc,"USD") or raw(cc,"USD")
    if inv: return 1.0/inv,cc
    if STRICT_FX: raise RuntimeError("FX missing")
    return 1.0,"USD"

def _mul_decimal(v,r=1.0):
    d=v if isinstance(v,Decimal) else Decimal(str(v))
    if r==1: return d
    return d*Decimal(str(r))

def _apply_precision(v,dp):
    if v is None: return None
    d=v if isinstance(v,Decimal) else Decimal(str(v))
    if dp is None: return d
    q=Decimal('1') if dp==0 else Decimal('1.'+'0'*dp)
    return d.quantize(q,rounding=ROUND_HALF_UP)

def _fetch_vwap_meta_by_run(conn,run_id,asset_id,qf):
    meta={"run_id":str(run_id),"providers":[],"total_volume":Decimal("0"),"computed_vwap":None}
    if not run_id or not asset_id or not qf:
        meta["error"]="missing run_id/asset_id/quote_fiat"; return meta
    join=_table_exists(conn,DATA_SOURCES_SCHEMA,DATA_SOURCES_TABLE)
    tbl=f"{SCHEMA}.{RAW_TICKS_TABLE}"
    if join:
        src=f"{DATA_SOURCES_SCHEMA}.{DATA_SOURCES_TABLE}"
        prov=f"COALESCE(s.{DATA_SOURCES_COL_NAME},'source:'||rpt.{RAW_COL_SOURCE_ID}::text)"
        j=f"LEFT JOIN {src} s ON s.{DATA_SOURCES_COL_ID}=rpt.{RAW_COL_SOURCE_ID}"
    else:
        prov=f"'source:'||rpt.{RAW_COL_SOURCE_ID}::text"; j=""
    sql=f"""
        SELECT {prov} AS provider,
               SUM(rpt.{RAW_COL_VOLUME}) AS vol,
               CASE WHEN SUM(rpt.{RAW_COL_VOLUME})>0
                    THEN SUM(rpt.{RAW_COL_VOLUME}*rpt.{RAW_COL_PRICE})/SUM(rpt.{RAW_COL_VOLUME})
                    ELSE NULL END AS pvwap
        FROM {tbl} rpt
        {j}
        WHERE rpt.{RAW_COL_RUN_ID}=:r AND rpt.{RAW_COL_ASSET_ID}=:a AND rpt.{RAW_COL_FIAT}=:q
        GROUP BY provider HAVING SUM(rpt.{RAW_COL_VOLUME})>0
        ORDER BY vol DESC NULLS LAST"""
    try: rows=conn.run(sql,r=run_id,a=asset_id,q=qf)
    except Exception as e:
        meta["error"]=str(e); return meta
    tot=Decimal("0"); num=Decimal("0"); out=[]
    for p,v,pv in rows:
        v=Decimal(str(v)); pv=Decimal(str(pv))
        tot+=v; num+=v*pv; out.append({"provider":p,"volume":v,"price":pv})
    meta["providers"]=out; meta["total_volume"]=tot
    meta["computed_vwap"]= (num/tot if tot>0 else None)
    if not out: meta["error"]="no_rows_for_run_asset_quote"
    return meta

def _infer_run_id_from_lineage(conn,vid):
    try:
        r=conn.run(f"""
        SELECT DISTINCT rpt.{RAW_COL_RUN_ID}
        FROM {SCHEMA}.valuation_inputs vi
        JOIN {SCHEMA}.{RAW_TICKS_TABLE} rpt ON rpt.id=vi.raw_tick_id
        WHERE vi.valuation_id=:v LIMIT 1""",v=vid)
        return r[0][0] if r else None
    except: return None

# =========================================================
# API-KEY HELPERS
# =========================================================

def _get_header(headers,name):
    if not headers: return None
    return headers.get(name) or headers.get(name.lower())

def _hash_secret(s): return hashlib.sha256(s.encode()).hexdigest()
def _constant_time_equal(a,b): return hmac.compare_digest(a,b)

def _is_hex_string(s):
    """Check if string is a valid hexadecimal string (for detecting already-hashed keys)."""
    try:
        int(s, 16)
        return len(s) == 64 and all(c in '0123456789abcdef' for c in s.lower())
    except:
        return False

def _validate_dynamodb_key(key_hash):
    """Validates API key against DynamoDB table.
    
    Args:
        key_hash (str): SHA-256 hash of the API key (64-char hex string).
    
    Returns:
        str: userId associated with the valid API key.
    
    Raises:
        ValueError: With reason code indicating failure reason.
    """
    try:
        logger.info(f"Querying DynamoDB table '{DYNAMODB_TABLE_NAME}' for API key (hash prefix: {key_hash[:8]}...)")
        
        # Query DynamoDB GSI on keyHash
        response = dynamodb.query(
            TableName=DYNAMODB_TABLE_NAME,
            IndexName='aPIKeysByKeyHash',
            KeyConditionExpression='keyHash = :kh',
            ExpressionAttributeValues={
                ':kh': {'S': key_hash}
            }
        )
        logger.info(f"DynamoDB query response: {response}")

        items = response.get('Items', [])
        if not items:
            logger.warning(f"API key not found in DynamoDB table '{DYNAMODB_TABLE_NAME}' (hash prefix: {key_hash[:8]}...)")
            raise ValueError("unknown_key")
        
        # Get the first item (should be unique by keyHash)
        item = items[0]
        logger.debug(f"Found API key record in DynamoDB (hash prefix: {key_hash[:8]}...)")
        
        # Extract fields from DynamoDB item
        status = item.get('status', {}).get('S', '')
        user_id = item.get('userId', {}).get('S')
        
        logger.debug(f"API key status: {status}, userId: {user_id}")
        
        # Check status
        if status != 'ACTIVE':
            logger.warning(f"API key validation failed: status is '{status}' (expected 'ACTIVE'), userId: {user_id}")
            raise ValueError("revoked")
        
        # Check expiration
        expires_at = None
        expires_at_raw = item.get('expiresAt')
        if expires_at_raw:
            # Handle both string (ISO) and number (Unix timestamp) formats
            if 'S' in expires_at_raw:
                expires_at_str = expires_at_raw['S']
                try:
                    # Parse ISO format datetime
                    expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                    else:
                        expires_at = expires_at.astimezone(timezone.utc)
                    logger.debug(f"API key expiresAt: {expires_at.isoformat()}")
                except Exception as e:
                    logger.warning(f"Error parsing expiresAt ISO string: {e}")
            elif 'N' in expires_at_raw:
                # Handle Unix timestamp (seconds since epoch)
                try:
                    expires_at = datetime.fromtimestamp(float(expires_at_raw['N']), tz=timezone.utc)
                    logger.debug(f"API key expiresAt (Unix): {expires_at.isoformat()}")
                except Exception as e:
                    logger.warning(f"Error parsing expiresAt Unix timestamp: {e}")
        else:
            logger.debug("API key has no expiration date")
        
        if expires_at:
            now = datetime.now(timezone.utc)
            if now > expires_at:
                logger.warning(f"API key validation failed: expired at {expires_at.isoformat()}, current time: {now.isoformat()}, userId: {user_id}")
                raise ValueError("expired")
        
        if not user_id:
            logger.error(f"API key record found but userId is missing (hash prefix: {key_hash[:8]}...)")
            raise ValueError("unknown_key")
        
        logger.info(f"API key validated successfully for userId: {user_id}")
        return user_id
        
    except ValueError as e:
        logger.error(f"DynamoDB query error for table '{DYNAMODB_TABLE_NAME}': {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"DynamoDB query error for table '{DYNAMODB_TABLE_NAME}': {e}", exc_info=True)
        raise ValueError("unknown_key")

def validate_api_key(conn,headers):
    """Validates X-API-Key from request headers.
    
    Supports two key formats:
    1. PostgreSQL format: "prefix.secret" (e.g., "5ec2fc9d9dda.1e3b58becf04cd0aea0612680bcd404155d7b815480d0961")
    2. DynamoDB format: 
       - "dacs_<64-char-alphanumeric>" (e.g., "dacs_nD2OrDloHNgvH6cVY8ofCzlMxNpjEZQTle5mBJ6EUK3R3CfwbIauXMRC7gXgGged")
         The entire key is hashed with SHA-256 before querying DynamoDB.
       - Already-hashed 64-char hex string (for direct hash lookup)
    
    Args:
        conn: Active PostgreSQL database connection (used for format 1).
        headers (dict): HTTP headers dictionary from Lambda event.
    
    Returns:
        str | int: User ID (DynamoDB) or Company ID (PostgreSQL) associated with valid key.
    
    Raises:
        ValueError: With reason code string indicating failure reason.
    """
    raw=_get_header(headers,"X-API-Key")
    if raw is None: raise ValueError("missing_header")
    
    # Check if key is DynamoDB format: "dacs_" prefix + 64 alphanumeric chars
    # Format: "dacs_<64-char-alphanumeric>" (e.g., "dacs_nD2OrDloHNgvH6cVY8ofCzlMxNpjEZQTle5mBJ6EUK3R3CfwbIauXMRC7gXgGged")
    if raw.startswith("dacs_"):
        # Hash the entire key (including "dacs_" prefix) with SHA-256 and query DynamoDB
        key_hash = _hash_secret(raw)
        logger.info(f"Hashed DynamoDB key: {key_hash}")
        return _validate_dynamodb_key(key_hash)
    
    # Check if key is already a 64-char hex string (SHA-256 hash, for direct lookup)
    if _is_hex_string(raw):
        # Query DynamoDB directly with the hash (no hashing needed)
        logger.info(f"Direct DynamoDB key: {raw}")
        return _validate_dynamodb_key(raw)
    
    # Otherwise, use existing PostgreSQL logic (prefix.secret format)
    if "." not in raw: raise ValueError("malformed")
    prefix,secret=raw.split(".",1)
    if not prefix or not secret: raise ValueError("malformed")
    r=conn.run(f"""
       SELECT key_hash,company_id,revoked,expires_at
       FROM {SCHEMA}.api_keys
       WHERE prefix=:p LIMIT 1""",p=prefix)
    if not r: raise ValueError("unknown_key")
    key_hash,cid,rev,exp=r[0]
    if rev: raise ValueError("revoked")
    now=datetime.now(timezone.utc)
    if exp and now>exp: raise ValueError("expired")
    if not _constant_time_equal(_hash_secret(secret),key_hash):
        raise ValueError("invalid_secret")
    return cid

# =========================================================
# MAIN HANDLER
# =========================================================

def lambda_handler(event, context):
    logger.info(f"Lambda handler called with event: {event}")
    conn=None
    try:
        params=event.get("queryStringParameters") or {}
        currency=(params.get("currency") or "USD").upper()
        scope=(params.get("scope") or "").lower()
        tz_str=params.get("tz")
        start_str=params.get("start")
        end_str=params.get("end")
        date_str=params.get("date")

        dp_param=params.get("decimals",params.get("dp"))
        decimals=None
        if dp_param is not None and str(dp_param).strip()!="":
            try:
                decimals=int(dp_param)
                if decimals<0 or decimals>18:
                    return {"statusCode":400,"body":json.dumps({"error":"decimals must be 0–18"})}
            except:
                return {"statusCode":400,"body":json.dumps({"error":"decimals must be int"})}

        target_ts=None; start_utc=None; end_utc=None

        out_tz_str=(params.get("out_tz") or "UTC").strip()
        m=re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*",out_tz_str)
        if m: out_tz_str=f"+{m.group(1).zfill(2)}:{m.group(2)}"
        try: out_tz=_parse_any_tz(out_tz_str)
        except Exception as e:
            return {"statusCode":400,"body":json.dumps({"error":str(e)})}

        if start_str or end_str:
            try: start_utc,end_utc=parse_range(start_str,end_str)
            except Exception as e:
                return {"statusCode":400,"body":json.dumps({"error":str(e)})}
        elif scope=="day" and date_str:
            if not tz_str:
                return {"statusCode":400,"body":json.dumps({"error":"scope=day requires tz"})}
            try: start_utc,end_utc=_local_day_bounds(date_str,tz_str)
            except Exception as e:
                return {"statusCode":400,"body":json.dumps({"error":str(e)})}
        elif date_str:
            try: target_ts=parse_target_timestamp(date_str,eod_tz=out_tz)
            except Exception as e:
                return {"statusCode":400,"body":json.dumps({"error":str(e)})}

        interval=(params.get("interval") or "").lower()
        agg=(params.get("agg") or "last").lower()
        bucket_sql=_get_bucket_sql(interval) if (start_utc and end_utc and interval) else None
        if bucket_sql and agg not in ("last","avg","min","max"):
            return {"statusCode":400,"body":json.dumps({"error":"agg must be last|avg|min|max"})}

        symbols=_parse_assets(event)
        if not symbols:
            return {"statusCode":400,"body":json.dumps({"error":"asset parameter is required"})}

        conn=pg8000.native.Connection(user=DB_USER,password=DB_PASSWORD,host=DB_HOST,port=DB_PORT,database=DB_NAME)

        #API KEY CHECK
        try:
            cid=validate_api_key(conn,event.get("headers") or {})
            logger.info(f"Authenticated user/company: {cid}")
        except ValueError as ve:
            msg={"missing_header":"X-API-Key header missing",
                 "malformed":"X-API-Key format invalid",
                 "unknown_key":"API key not found",
                 "revoked":"API key revoked",
                 "expired":"API key expired",
                 "invalid_secret":"API key invalid"}.get(str(ve),str(ve))
            return {"statusCode":401,"body":json.dumps({"error":"Unauthorized","reason":msg})}

        fx_rate,_=_fetch_fx(conn,currency)

        asset_rows=conn.run(f"SELECT symbol,id FROM {SCHEMA}.crypto_assets WHERE symbol=ANY(:s)",s=symbols)
        sym_to_id={a:b for a,b in asset_rows}
        if not sym_to_id:
            return {"statusCode":404,"body":json.dumps({"error":f"No matching assets for {symbols}"})}

        # -------------------------------------------------------
        # FETCH VALUATION DATA
        # -------------------------------------------------------
        def fetch_ccy(q):
            if start_utc and end_utc:
                if bucket_sql:
                    agg_sql={"avg":"AVG","min":"MIN","max":"MAX","last":"(ARRAY_AGG(vv.canonical_price ORDER BY vv.valuation_ts DESC))[1]"}[agg]
                    sql=f"""
                    SELECT ca.symbol,{bucket_sql} AS ts,{agg_sql}(vv.canonical_price)
                    FROM {SCHEMA}.crypto_assets ca
                    JOIN {SCHEMA}.valuations vv ON vv.asset_id=ca.id
                    WHERE ca.symbol=ANY(:s) AND vv.quote_fiat=:q
                      AND vv.valuation_ts>=:a AND vv.valuation_ts<=:b
                    GROUP BY ca.symbol,ts
                    ORDER BY ca.symbol,ts"""
                    return conn.run(sql,s=symbols,q=q,a=start_utc,b=end_utc)
                else:
                    sql=f"""
                    SELECT ca.symbol,vv.valuation_ts,vv.canonical_price
                    FROM {SCHEMA}.crypto_assets ca
                    JOIN {SCHEMA}.valuations vv ON vv.asset_id=ca.id
                    WHERE ca.symbol=ANY(:s) AND vv.quote_fiat=:q
                      AND vv.valuation_ts>=:a AND vv.valuation_ts<=:b
                    ORDER BY ca.symbol,vv.valuation_ts"""
                    return conn.run(sql,s=symbols,q=q,a=start_utc,b=end_utc)
            else:
                if target_ts:
                    sql=f"""
                    SELECT ca.symbol,v.canonical_price,v.valuation_ts,v.id
                    FROM {SCHEMA}.crypto_assets ca
                    JOIN LATERAL (
                       SELECT id,canonical_price,valuation_ts
                       FROM {SCHEMA}.valuations vv
                       WHERE vv.asset_id=ca.id AND vv.quote_fiat=:q
                         AND vv.valuation_ts<=:t
                       ORDER BY valuation_ts DESC LIMIT 1
                    ) v ON TRUE
                    WHERE ca.symbol=ANY(:s)"""
                    return conn.run(sql,q=q,t=target_ts,s=symbols)
                else:
                    sql=f"""
                    SELECT ca.symbol,v.canonical_price,v.valuation_ts,v.id
                    FROM {SCHEMA}.crypto_assets ca
                    JOIN LATERAL (
                       SELECT id,canonical_price,valuation_ts
                       FROM {SCHEMA}.valuations vv
                       WHERE vv.asset_id=ca.id AND vv.quote_fiat=:q
                       ORDER BY valuation_ts DESC LIMIT 1
                    ) v ON TRUE
                    WHERE ca.symbol=ANY(:s)"""
                    return conn.run(sql,q=q,s=symbols)

        rows_req=fetch_ccy(currency)

        def to_out(ts):
            if ts is None: return None
            return (ts.astimezone(out_tz) if ts.tzinfo else ts.replace(tzinfo=timezone.utc).astimezone(out_tz))

        def build_snapshot(rows,ccy,mult=1.0,conv=False,meta_q=None):
            found={r[0]:(r[1],r[2],(r[3] if len(r)>3 else None)) for r in rows}
            out=[]
            for sym in symbols:
                if sym in found:
                    price,ts,vid=found[sym]
                    p=_apply_precision(_mul_decimal(price,mult),decimals)
                    ts2=to_out(ts)
                    item={'asset':sym,'currency':ccy,'price':p,'timestamp':ts2.isoformat() if ts2 else None}
                    if conv: item['converted_from']="USD"
                    q=meta_q or ccy
                    run_id=_infer_run_id_from_lineage(conn,vid) if vid else None
                    try:
                        aid=sym_to_id.get(sym)
                        if run_id:
                            item['metadata']=_fetch_vwap_meta_by_run(conn,run_id,aid,q)
                        else:
                            item['metadata']={"run_id":None,"providers":[],"total_volume":Decimal("0"),"computed_vwap":None,"error":"missing run_id"}
                    except Exception as e:
                        item['metadata']={"run_id":str(run_id),"error":str(e)}
                    out.append(item)
                else:
                    out.append({"asset":sym,"currency":ccy,"error":f"No price data for {sym}"})
            return out

        # -------------------------------------------------------
        # RANGE MODE
        # -------------------------------------------------------
        if start_utc and end_utc:
            def build_points(rows,m=1.0):
                d={s:[] for s in symbols}
                if bucket_sql:
                    for sym,ts,p in rows:
                        ts2=to_out(ts)
                        d[sym].append({"timestamp":ts2.isoformat(),"price":_apply_precision(_mul_decimal(p,m),decimals)})
                else:
                    for sym,ts,p in rows:
                        ts2=to_out(ts)
                        d[sym].append({"timestamp":ts2.isoformat(),"price":_apply_precision(_mul_decimal(p,m),decimals)})
                return d
            if any(rows_req):
                pts=build_points(rows_req,1.0)
                if len(symbols)==1:
                    body={"asset":symbols[0],"currency":currency,"out_tz":out_tz_str,
                          "range":{"start":start_utc.isoformat(),"end":end_utc.isoformat()},
                          "points":pts[symbols[0]]}
                else:
                    body={"currency":currency,"out_tz":out_tz_str,
                          "range":{"start":start_utc.isoformat(),"end":end_utc.isoformat()},
                          "results":[{"asset":s,"points":pts[s]} for s in symbols]}
                return {"statusCode":200,"headers":{"Content-Type":"application/json"},"body":json.dumps(body,default=decimal_to_float)}
            rows_usd=fetch_ccy("USD")
            if rows_usd and CONVERT_IF_MISSING and currency!="USD":
                pts=build_points(rows_usd,fx_rate)
                if len(symbols)==1:
                    body={"asset":symbols[0],"currency":currency,"converted_from":"USD",
                          "fx":{"base":"USD","quote":currency,"rate":fx_rate},
                          "out_tz":out_tz_str,
                          "range":{"start":start_utc.isoformat(),"end":end_utc.isoformat()},
                          "points":pts[symbols[0]]}
                else:
                    body={"currency":currency,"converted_from":"USD",
                          "fx":{"base":"USD","quote":currency,"rate":fx_rate},
                          "out_tz":out_tz_str,
                          "range":{"start":start_utc.isoformat(),"end":end_utc.isoformat()},
                          "results":[{"asset":s,"points":pts[s]} for s in symbols]}
                return {"statusCode":200,"body":json.dumps(body,default=decimal_to_float)}
            return {"statusCode":404,"body":json.dumps({"error":f"No price data for {symbols}"})}

        # -------------------------------------------------------
        # SNAPSHOT MODE
        # -------------------------------------------------------
        if rows_req:
            results=build_snapshot(rows_req,currency,1.0,False,currency)
        else:
            rows_usd=fetch_ccy("USD")
            if rows_usd:
                if CONVERT_IF_MISSING and currency!="USD":
                    results=build_snapshot(rows_usd,currency,fx_rate,True,"USD")
                else:
                    results=build_snapshot(rows_usd,"USD",1.0,False,"USD")
                    if currency!="USD":
                        for r in results:
                            if "price" in r:
                                r["fx"]={"base":"USD","quote":currency,"rate":fx_rate}
            else:
                results=[{"asset":s,"currency":currency,"error":f"No price data for {s}"} for s in symbols]

        # -------------------------------------------------------
        # FINAL RESPONSE
        # -------------------------------------------------------
        if len(symbols)==1 and len(results)==1 and "price" in results[0]:
            body=results[0]; body["out_tz"]=out_tz_str
        else:
            body={"results":results,"out_tz":out_tz_str}
            cc={r.get("currency") for r in results if "currency" in r}
            if len(cc)==1: body["currency"]=list(cc)[0]
        return {"statusCode":200,"headers":{"Content-Type":"application/json"},
                "body":json.dumps(body,default=decimal_to_float)}

    except Exception as e:
        logger.exception("Unhandled error")
        return {"statusCode":500,"body":json.dumps({"error":"Internal server error","detail":str(e)})}

    finally:
        if conn:
            try: conn.close()
            except: pass
