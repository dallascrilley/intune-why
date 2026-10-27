// Record the README demo from a generated report. Needs Playwright and Google Chrome.
// Usage: node scripts/record-demo.cjs report.html out-dir
// Then:  ffmpeg -i out-dir/<video>.webm -filter_complex "fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen[p];[b][p]paletteuse" docs/demo.gif
const { chromium } = require("playwright");

(async () => {
  const [report, outDir] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true, channel: process.env.PW_CHANNEL || "chrome" });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    colorScheme: "light",
    recordVideo: { dir: outDir, size: { width: 1280, height: 800 } },
  });
  const page = await context.newPage();
  await page.addInitScript(() => {
    addEventListener("DOMContentLoaded", () => {
      const c = document.createElement("div");
      c.style.cssText = "position:fixed;width:20px;height:20px;z-index:9999;pointer-events:none;border-radius:50%;border:3px solid #fff;background:#17212c;box-shadow:0 1px 6px #0006;transform:translate(-50%,-50%);left:640px;top:640px;transition:transform .12s";
      document.body.append(c);
      addEventListener("mousemove", (e) => { c.style.left = e.clientX + "px"; c.style.top = e.clientY + "px"; });
      addEventListener("mousedown", () => { c.style.transform = "translate(-50%,-50%) scale(.75)"; });
      addEventListener("mouseup", () => { c.style.transform = "translate(-50%,-50%)"; });
    });
  });
  await page.goto(new URL(report, "file://" + process.cwd() + "/").href);
  await page.mouse.move(640, 640);
  await page.waitForTimeout(700);
  const clickCenter = async (locator, steps = 18) => {
    const box = await locator.boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps });
    await page.waitForTimeout(150);
    await page.mouse.down();
    await page.mouse.up();
  };
  await clickCenter(page.locator("#simulate"));
  await page.waitForTimeout(2300);
  await clickCenter(page.locator(".row:has(.chip.jev) .title").first(), 22);
  await page.waitForTimeout(2200);
  const video = page.video();
  await context.close();
  await browser.close();
  console.log(await video.path());
})().catch((e) => { console.error(e); process.exit(1); });
