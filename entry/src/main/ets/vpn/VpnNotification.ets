import { notificationManager } from '@kit.NotificationKit';
import { wantAgent, WantAgent } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

const TAG = 'BiuNotify';
const DOMAIN_ID = 0x0000;
const NOTIFY_ID = 1001;
const UPDATE_INTERVAL_MS = 2000;

interface StatsData {
  running: boolean;
  dnsQueries: number;
  acceleratedQueries: number;
}

export class VpnNotification {
  private timer: number = -1;
  private agent: WantAgent | undefined = undefined;
  private statsPath: string;
  private disabled: boolean = false;

  constructor(filesDir: string) {
    this.statsPath = `${filesDir}/biu_stats.json`;
  }

  async start(): Promise<void> {
    try {
      this.agent = await wantAgent.getWantAgent({
        wants: [{
          bundleName: 'com.biu.app',
          abilityName: 'EntryAbility'
        }],
        actionType: wantAgent.OperationType.START_ABILITY,
        requestCode: 0,
        wantAgentFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
      });
    } catch (e) {
      hilog.warn(DOMAIN_ID, TAG, 'wantAgent failed: %{public}s', JSON.stringify(e));
    }

    await this.publish();
    if (this.disabled) return;
    if (this.timer === -1) {
      this.timer = setInterval(() => {
        this.publish();
      }, UPDATE_INTERVAL_MS);
    }
  }

  stop(): void {
    if (this.timer !== -1) {
      clearInterval(this.timer);
      this.timer = -1;
    }
    notificationManager.cancel(NOTIFY_ID).catch((err: Error) => {
      hilog.warn(DOMAIN_ID, TAG, 'cancel failed: %{public}s', JSON.stringify(err));
    });
  }

  private readStats(): StatsData | null {
    try {
      return JSON.parse(fs.readTextSync(this.statsPath)) as StatsData;
    } catch (e) {
      return null;
    }
  }

  private async publish(): Promise<void> {
    if (this.disabled) return;

    let text = '正在转发 GitHub 流量';
    const stats = this.readStats();
    if (stats !== null) {
      text = `DNS 请求 ${stats.dnsQueries} · 已加速 ${stats.acceleratedQueries}`;
    }

    const request: notificationManager.NotificationRequest = {
      id: NOTIFY_ID,
      notificationSlotType: notificationManager.SlotType.CONTENT_INFORMATION,
      isOngoing: true,
      isAlertOnce: true,
      content: {
        notificationContentType: notificationManager.ContentType.NOTIFICATION_CONTENT_BASIC_TEXT,
        normal: {
          title: 'Biu 加速中',
          text: text
        }
      },
      wantAgent: this.agent
    };

    try {
      await notificationManager.publish(request);
    } catch (e) {
      const code = (e as BusinessError).code;
      hilog.warn(DOMAIN_ID, TAG, 'publish failed: %{public}d', code);
      if (code === 1600004) {
        this.disabled = true;
        if (this.timer !== -1) {
          clearInterval(this.timer);
          this.timer = -1;
        }
      }
    }
  }
}
