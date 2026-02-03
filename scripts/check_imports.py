import importlib, sys
mods = ["pandas","numpy","sklearn","xgboost","pyarrow","pydantic","joblib","fastapi","uvicorn","catboost"]
res = {}
for m in mods:
    try:
        importlib.import_module(m)
        res[m] = "ok"
    except Exception as e:
        res[m] = "missing: {}: {}".format(type(e).__name__, e)
print(sys.executable)
print(res)
