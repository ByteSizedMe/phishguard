import express from "express";
import analyzeRouter from "./routes/analyze.routes";

const app = express();
const PORT = 3000;

app.use(express.json());
app.use("/api/analyze", analyzeRouter);

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});