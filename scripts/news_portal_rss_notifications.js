#!/usr/bin/env node
"use strict";

require("dotenv").config();

const { setTimeout: sleep } = require("timers/promises");
const {
  createNewsPortalRssNotificationService,
} = require("../src/newsPortalRssNotificationService");

const command = process.argv[2] || "check";
const flags = parseFlags(process.argv.slice(3));
const service = createNewsPortalRssNotificationService({
  delayRange: flags.delay || undefined,
});

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function run() {
  if (command === "check") {
    const result = await service.checkRssAndScheduleNotifications({
      dryRun: flags.dryRun,
      persist: !flags.noPersist,
      seedWhenEmpty: flags.seed !== false,
    });
    printResult(result);
    return;
  }

  if (command === "dispatch") {
    const result = await service.dispatchDueNotifications({
      dryRun: flags.dryRun,
      persist: !flags.noPersist,
    });
    printResult(result);
    return;
  }

  if (command === "run") {
    const scheduled = await service.checkRssAndScheduleNotifications({
      dryRun: flags.dryRun,
      persist: !flags.noPersist,
      seedWhenEmpty: flags.seed !== false,
    });
    const dispatched = await service.dispatchDueNotifications({
      dryRun: flags.dryRun,
      persist: !flags.noPersist,
    });
    printResult({ scheduled, dispatched });
    return;
  }

  if (command === "start") {
    await startScheduler(service, flags);
    return;
  }

  throw new Error(`Bilinmeyen komut: ${command}`);
}

async function startScheduler(currentService, currentFlags) {
  const dispatchIntervalMs =
    Number.parseInt(process.env.NEWS_PORTAL_DISPATCH_INTERVAL_SECONDS || "60", 10) *
    1000;
  const checkIntervalMs =
    Number.parseInt(process.env.NEWS_PORTAL_CHECK_INTERVAL_MINUTES || "60", 10) *
    60 *
    1000;

  console.log("Yeni Asya Haber Portalı RSS bildirim scheduler başladı.");
  console.log(
    `RSS kontrol: ${checkIntervalMs / 60000} dk, dispatch: ${
      dispatchIntervalMs / 1000
    } sn`
  );

  let nextCheckAt = 0;
  while (true) {
    const now = Date.now();
    if (now >= nextCheckAt) {
      const scheduled = await currentService.checkRssAndScheduleNotifications({
        dryRun: currentFlags.dryRun,
        persist: !currentFlags.noPersist,
        seedWhenEmpty: currentFlags.seed !== false,
      });
      console.log(`[check] ${JSON.stringify(scheduled)}`);
      nextCheckAt = now + checkIntervalMs;
    }

    const dispatched = await currentService.dispatchDueNotifications({
      dryRun: currentFlags.dryRun,
      persist: !currentFlags.noPersist,
    });
    if (dispatched.dueCount > 0 || dispatched.failedCount > 0) {
      console.log(`[dispatch] ${JSON.stringify(dispatched)}`);
    }
    await sleep(dispatchIntervalMs);
  }
}

function parseFlags(args) {
  const flags = {
    dryRun: false,
    noPersist: false,
    seed: true,
    delay: undefined,
  };

  for (const arg of args) {
    if (arg === "--dry-run") flags.dryRun = true;
    if (arg === "--no-persist") flags.noPersist = true;
    if (arg === "--seed=false") flags.seed = false;
    if (arg.startsWith("--delay=")) {
      const [minRaw, maxRaw] = arg.slice("--delay=".length).split(",");
      flags.delay = [
        Number.parseInt(minRaw || "0", 10),
        Number.parseInt(maxRaw || minRaw || "0", 10),
      ];
    }
  }

  return flags;
}

function printResult(result) {
  console.log(JSON.stringify(result, null, 2));
}
