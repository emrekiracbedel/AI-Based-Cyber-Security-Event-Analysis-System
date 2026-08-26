const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("miniSiem", {
  platform: process.platform,
});
