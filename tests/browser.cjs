/* End-to-end checks against a temporary workspace and a real Chromium browser. */
const { chromium } = require("playwright");
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const assert = require("node:assert/strict");

(async () => {
  const root = path.resolve(__dirname, ".."),
    temp = fs.mkdtempSync(path.join(os.tmpdir(), "securefi-browser-"));
  const python = process.env.PYTHON || "python3",
    auth = path.join(temp, "access.json"),
    db = path.join(temp, "app.db");
  let server, browser;
  try {
    const prep = spawnSync(
      python,
      ["-m", "securefi", "app", "--db", db, "--auth", auth, "demo"],
      { cwd: root, encoding: "utf8" },
    );
    assert.equal(prep.status, 0, prep.stderr);
    const output = prep.stdout.slice(prep.stdout.indexOf("{"));
    const tokens = JSON.parse(output.slice(0, output.indexOf("\n}\n") + 2));
    server = spawn(
      python,
      [
        "-m",
        "securefi",
        "app",
        "--db",
        db,
        "--auth",
        auth,
        "serve",
        "--port",
        "0",
      ],
      { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
    );
    const url = await new Promise((resolve, reject) => {
      let output = "";
      const timer = setTimeout(
        () => reject(Error("Server startup timed out")),
        15000,
      );
      server.stdout.on("data", (data) => {
        output += data;
        const found = output.match(/http:\/\/127\.0\.0\.1:\d+/);
        if (found) {
          clearTimeout(timer);
          resolve(found[0]);
        }
      });
      server.on("error", reject);
    });
    browser = await chromium.launch({
      headless: true,
      ...(process.env.SECUREFI_BROWSER_PATH
        ? { executablePath: process.env.SECUREFI_BROWSER_PATH }
        : {}),
      ...(process.env.SECUREFI_BROWSER_ARGS
        ? { args: JSON.parse(process.env.SECUREFI_BROWSER_ARGS) }
        : {}),
    });
    const page = await browser.newPage({
        viewport: { width: 1440, height: 1000 },
      }),
      errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(url);
    const wait = async () => {
      await page.waitForFunction(() => !document.querySelector("#modal").open);
    };
    const login = async (role) => {
      await page.locator("#token").fill(tokens[role]);
      await page.locator("#login-form button").click();
      await page.locator("#workspace").waitFor({ state: "visible" });
    };
    const tab = async (name) => {
      await page.locator(`[data-tab="${name}"]`).click();
    };
    await login("analyst");
    for (const name of [
      "soc",
      "alerts",
      "cases",
      "assets",
      "detections",
      "cloud",
      "ai",
      "web3",
      "compliance",
      "activity",
    ]) {
      await tab(name);
      if (name === "activity")
        await page
          .getByRole("heading", { name: "Recent changes and decisions" })
          .waitFor();
      assert.ok((await page.locator("#content").innerText()).length > 50, name);
    }
    await tab("alerts");
    await page.locator("#search").fill("SF-029");
    assert.ok(
      (await page.locator("#alert-results").innerText()).includes("SF-029"),
    );
    await page.locator("[data-alert]").first().click();
    await page.locator("#triage-form [name=status]").selectOption("triaged");
    await page
      .locator("#triage-form [name=note]")
      .fill("Reviewed synthetic source observation");
    await page.locator("#triage-form button").click();
    await wait();
    await page.locator("[data-alert]").first().click();
    await page.locator("[data-event]").first().click();
    await page.waitForFunction(
      () =>
        document.querySelector("#modal-title").textContent ===
        "Source observation",
    );
    assert.ok(
      (await page.locator("#modal-body").innerText()).includes("synthetic"),
    );
    await page.locator("#close").click();
    await page.locator("[data-alert]").first().click();
    await page
      .locator("#case-form textarea")
      .fill("Validate AI permission observation");
    await page.locator("#case-form button").click();
    await wait();
    await tab("assets");
    await page.locator("[data-asset]").first().click();
    await page.locator("#asset-form [name=owner]").fill("Security operations");
    await page.locator("#asset-form [name=criticality]").selectOption("5");
    await page
      .locator("#asset-form textarea")
      .fill("Confirmed service ownership");
    await page.locator("#asset-form button").click();
    await wait();
    assert.ok(
      (await page.locator("#content").innerText()).includes(
        "Security operations",
      ),
    );
    await tab("cases");
    await page.locator("[data-case]").first().click();
    await page.locator("[data-draft]").click();
    await page.locator("[data-draft-review]").waitFor();
    assert.ok(
      (await page.locator("#modal-body").innerText()).includes(
        "Deterministic fallback",
      ),
    );
    await page.locator("[data-draft-review]").click();
    await page
      .locator("#draft-review-form textarea")
      .fill("Validated recommendations against the observation");
    await page.locator("#draft-review-form button").click();
    await wait();
    await page.locator("[data-case]").first().click();
    await page
      .locator("#case-update-form textarea[name=note]")
      .fill("Owner confirmed scope; source references retained");
    await page.locator("#case-update-form button").click();
    await wait();
    await page.locator("[data-request]").first().click();
    await page.locator("#run-form button").click();
    await wait();
    assert.equal(
      await page.locator("[data-approve]").count(),
      0,
      "Analyst must not be offered approval",
    );
    await page.locator("#logout").click();
    await login("approver");
    await tab("cases");
    await page.locator("[data-approve]").click();
    await page
      .locator("#approve-form textarea")
      .fill("Independent approval for bounded simulation");
    await page.locator("#approve-form button").click();
    await wait();
    await page.locator("[data-execute]").click();
    await page.locator("[data-rollback]").waitFor();
    await page.locator("[data-rollback]").click();
    await page.waitForFunction(() =>
      document.querySelector("#content").textContent.includes("rolled back"),
    );
    await page.locator("#logout").click();
    await login("compliance");
    await tab("compliance");
    await page.locator("#report").click();
    await page.locator("[data-evidence]").waitFor();
    const downloading = page.waitForEvent("download");
    await page.locator("[data-evidence]").click();
    const downloaded = await downloading;
    const report = JSON.parse(fs.readFileSync(await downloaded.path(), "utf8"));
    assert.equal(report.document.schema, "securefi-evidence/v3");
    assert.ok(report.document.cases.length);
    await page.locator("[data-ledger-verify]").click();
    await page.waitForFunction(() =>
      document
        .querySelector("#modal-body")
        .textContent.includes("has not been recorded"),
    );
    await page.locator("#close").click();
    await page.locator("#audit").click();
    await page.waitForFunction(() =>
      document.querySelector("#notice").textContent.includes('"valid":true'),
    );
    await page.locator("#logout").click();
    await login("executive");
    assert.equal(await page.locator("[data-tab=alerts]:visible").count(), 0);
    await page.locator("#logout").click();
    await login("analyst");
    await tab("soc");
    await page.locator("#import").click();
    const imported = {
      event_id: "browser-import",
      synthetic: true,
      source: "cloud",
      time: "2026-10-21T10:00:00Z",
      data: {
        operation: "storage_update",
        asset: "imported-store",
        public: false,
        encrypted: true,
      },
    };
    await page.locator("#import-form input[type=file]").setInputFiles({
      name: "events.jsonl",
      mimeType: "application/x-ndjson",
      buffer: Buffer.from(JSON.stringify(imported) + "\n"),
    });
    await page.locator("#import-form button").click();
    await wait();
    await page.waitForFunction(() =>
      document
        .querySelector("#notice")
        .textContent.includes("1 accepted, 0 duplicates"),
    );
    const response = await page.request.get(url + "/api/state", {
      headers: { Authorization: "Bearer " + tokens.analyst },
    });
    const before = (await response.json()).metrics.events;
    await page.locator("#load-samples").click();
    await page.waitForFunction(() =>
      document.querySelector("#notice").textContent.includes("deduplicated"),
    );
    const after = await page.request.get(url + "/api/state", {
      headers: { Authorization: "Bearer " + tokens.analyst },
    });
    assert.equal((await after.json()).metrics.events, before);
    await page.setViewportSize({ width: 390, height: 844 });
    const fits = await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth + 1,
    );
    if (!fits)
      console.error(
        await page.evaluate(() =>
          Array.from(document.querySelectorAll("*"))
            .filter(
              (e) => e.getBoundingClientRect().right > window.innerWidth + 1,
            )
            .slice(0, 15)
            .map((e) => [
              e.tagName,
              e.id,
              e.className,
              Math.round(e.getBoundingClientRect().right),
            ]),
        ),
      );
    assert.ok(fits, "Mobile page overflows horizontally");
    if (process.env.SECUREFI_QA_SCREENSHOT) {
      await page.setViewportSize({ width: 1440, height: 1000 });
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({
        path: process.env.SECUREFI_QA_SCREENSHOT,
        fullPage: true,
      });
    }
    assert.deepEqual(errors, []);
    console.log(
      "PASS: 10 views, search, triage, evidence drill-down, case updates, assets, advisory draft review, separate response approval, execution/rollback, evidence download, audit verification, JSONL import, sample replay, executive privacy and mobile layout.",
    );
  } finally {
    if (browser) await browser.close();
    if (server) {
      server.kill();
      if (server.exitCode === null)
        await new Promise((resolve) => server.once("exit", resolve));
    }
    fs.rmSync(temp, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
