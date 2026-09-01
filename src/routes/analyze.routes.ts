import Router from "express";
import analyzeUrl from "../services/url-analyzer.service";

const analyzeRouter = Router();

analyzeRouter.post("/", (req, res) => {
    const url = req.body.url;

    if(url == null){
        res.status(400).json({error: "URL is required"});
        return;
    } 

    if(typeof url !== "string"){
        res.status(400).json({error: "URL is not a string"});
        return;
    }

    if(url.trim() === ""){
        res.status(400).json({error: "URL is empty"});
        return;
    }

    try{
        const result = analyzeUrl(url);
        res.json(result);
    }
    catch{
        res.status(400).json({error: "Invalid URL"});
        return;
    }
});

export default analyzeRouter;