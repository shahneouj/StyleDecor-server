const fs = require("fs");
const key = fs.readFileSync("./styledecor-45ebb-firebase-adminsdk-fbsvc-2cb7ac5bb5.json", "utf8");
const base64 = Buffer.from(key).toString("base64");
console.log(base64);