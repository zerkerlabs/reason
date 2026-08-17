import { cp, mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await mkdir("dist", { recursive: true });
for (const file of ["index.html", "app.js", "styles.css", "reason.css"]) {
  await cp(file, `dist/${file}`);
}
await cp("data", "dist/data", { recursive: true });
console.log("Zerker Reason site built in dist/");
