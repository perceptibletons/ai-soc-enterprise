from fastapi import FastAPI
from routes import generator
from routes import ingest

app = FastAPI()

app.include_router(generator.router)   # 🔥 IMPORTANT
app.include_router(ingest.router)

@app.get("/")
def home():
    return {"message": "AI-SOC Backend Running"}