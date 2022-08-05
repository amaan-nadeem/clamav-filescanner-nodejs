const express = require("express");
const cors = require("cors");
const fileUpload = require("express-fileupload");
const NodeClam = require("clamscan");
const Readable = require("stream").Readable;

const { clamscanConfig, fileUploadConfig } = require("./config/clamscan");
const app = express();
const port = 3000;

// CORS Middleware
app.use(cors());

// Middleware for attaching clamscan with the express request
app.use(async (req, _, next) => {
  req.clamscan = await new NodeClam().init({ ...clamscanConfig });
  next();
});

// Middleware for attaching files to req.files
app.use(fileUpload({ ...fileUploadConfig }));

const scanFile = async (file, clamscan) => {
  const fileStream = Readable();
  fileStream.push(file.data);
  fileStream.push(null);

  const result = await clamscan.scanStream(fileStream);

  return {
    filename: file.name,
    is_infected: result.isInfected,
    viruses: result.viruses,
  };
};

// POST: /avatar-upload route
app.post("/avatar-upload", async (req, res) => {
  if (!req.files || !req.files.avatar) {
    return res.status(409).json({
      message: "No file uploaded!",
    });
  }

  const avatar = req.files.avatar;

  const scanResult = await scanFile(avatar, req.clamscan);

  console.log(scanResult);

  if (!scanResult.is_infected) {
    avatar.mv("./uploads/" + avatar.name);
    return res.status(200).json({
      message: "File successfully uploaded!",
    });
  }

  return res.status(502).json({
    message: "Malicious file found!",
  });
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
