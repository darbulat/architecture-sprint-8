import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Update the algorithm to RS256
ALGORITHM = "RS256"


@app.get("/reports")
async def get_reports() -> StreamingResponse:
    report_file_path = os.path.abspath("./report.pdf")
    return FileResponse(report_file_path, media_type="application/pdf", filename="report.pdf")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
