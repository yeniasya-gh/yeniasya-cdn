"use strict";

const {
  createNewsPortalRssNotificationService,
} = require("./newsPortalRssNotificationService");

class YeniAsyaHaberPortaliNotificationController {
  constructor(options = {}) {
    this.service = options.service || createNewsPortalRssNotificationService(options);
  }

  async checkRssAndScheduleNotifications(options = {}) {
    return this.service.checkRssAndScheduleNotifications(options);
  }

  async dispatchDueNotifications(options = {}) {
    return this.service.dispatchDueNotifications(options);
  }

  async runOnce(options = {}) {
    const scheduled = await this.checkRssAndScheduleNotifications(options);
    const dispatched = await this.dispatchDueNotifications(options);
    return { scheduled, dispatched };
  }
}

function createYeniAsyaHaberPortaliNotificationRouter(express, options = {}) {
  if (!express || !express.Router) {
    throw new Error("Express Router bekleniyor.");
  }

  const router = express.Router();
  const authMiddleware = options.authMiddleware || ((_req, _res, next) => next());
  const controller =
    options.controller || new YeniAsyaHaberPortaliNotificationController(options);

  router.post(
    "/news-portal/rss-notifications/check",
    authMiddleware,
    async (req, res, next) => {
      try {
        const result = await controller.checkRssAndScheduleNotifications({
          dryRun: req.body && req.body.dryRun === true,
          seedWhenEmpty: !(req.body && req.body.seedWhenEmpty === false),
        });
        res.json({ ok: true, result });
      } catch (error) {
        next(error);
      }
    }
  );

  router.post(
    "/news-portal/rss-notifications/dispatch",
    authMiddleware,
    async (req, res, next) => {
      try {
        const result = await controller.dispatchDueNotifications({
          dryRun: req.body && req.body.dryRun === true,
        });
        res.json({ ok: true, result });
      } catch (error) {
        next(error);
      }
    }
  );

  router.post(
    "/news-portal/rss-notifications/run",
    authMiddleware,
    async (req, res, next) => {
      try {
        const result = await controller.runOnce({
          dryRun: req.body && req.body.dryRun === true,
          seedWhenEmpty: !(req.body && req.body.seedWhenEmpty === false),
        });
        res.json({ ok: true, result });
      } catch (error) {
        next(error);
      }
    }
  );

  return router;
}

module.exports = {
  YeniAsyaHaberPortaliNotificationController,
  createYeniAsyaHaberPortaliNotificationRouter,
};
