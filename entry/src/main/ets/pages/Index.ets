import { vpnExtension } from '@kit.NetworkKit';
import { common, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { fileIo as fs } from '@kit.CoreFileKit';
import { notificationManager } from '@kit.NotificationKit';
import { ConnectivityTest, ProbeOutcome } from '../net/ConnectivityTest';

const TAG = 'BiuUI';
const DOMAIN_ID = 0x0000;

interface StatsData {
  running: boolean;
  dnsQueries: number;
  acceleratedQueries: number;
}

interface ProbeRow {
  name: string;
  done: boolean;
  ok: boolean;
  detail: string;
}

const GITHUB_DOMAINS: string[] = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'gist.github.com',
  'github.githubassets.com',
  'avatars.githubusercontent.com',
  'objects.githubusercontent.com',
  'github.io',
  'github.global.ssl.fastly.net',
  'collector.github.com',
  'central.github.com',
  'github.community',
  'github.blog',
  'githubusercontent.com',
];

@Entry
@Component
struct Index {
  @State isRunning: boolean = false;
  @State dnsQueries: number = 0;
  @State acceleratedQueries: number = 0;
  @State statusText: string = '未启动';
  @State testing: boolean = false;
  @State probes: ProbeRow[] = [
    { name: 'DNS 解析', done: false, ok: false, detail: '未测试' },
    { name: 'github.com', done: false, ok: false, detail: '未测试' },
    { name: 'api.github.com', done: false, ok: false, detail: '未测试' },
  ];
  private statsTimer: number = -1;
  private statsFilePath: string = '';
  private statsReadFailed: boolean = false;

  aboutToAppear(): void {
    this.startStatsPolling();
    setTimeout(() => {
      this.runProbes();
    }, 500);
  }

  aboutToDisappear(): void {
    this.stopStatsPolling();
  }

  private statsIsFresh(): boolean {
    try {
      const st = fs.statSync(this.statsFilePath);
      const nowSec = Math.floor(Date.now() / 1000);
      return (nowSec - st.mtime) <= 5;
    } catch (e) {
      return false;
    }
  }

  private startStatsPolling(): void {
    if (this.statsTimer !== -1) return;
    if (this.statsFilePath === '') {
      try {
        this.statsFilePath = `${getContext(this).filesDir}/biu_stats.json`;
        hilog.info(DOMAIN_ID, TAG, 'stats path: %{public}s', this.statsFilePath);
      } catch (e) {
        hilog.error(DOMAIN_ID, TAG, 'get filesDir failed: %{public}s', JSON.stringify(e));
        return;
      }
    }
    this.statsTimer = setInterval(() => {
      try {
        const text = fs.readTextSync(this.statsFilePath);
        const stats = JSON.parse(text) as StatsData;
        const running = stats.running && this.statsIsFresh();
        this.isRunning = running;
        this.dnsQueries = stats.dnsQueries;
        this.acceleratedQueries = stats.acceleratedQueries;
        this.statusText = running ? '加速中' : '未启动';
        this.statsReadFailed = false;
      } catch (e) {
        if (!this.statsReadFailed) {
          this.statsReadFailed = true;
          hilog.warn(DOMAIN_ID, TAG, 'stats read failed: %{public}s %{public}s',
            this.statsFilePath, JSON.stringify(e));
        }
      }
    }, 1000);
  }

  private stopStatsPolling(): void {
    if (this.statsTimer !== -1) {
      clearInterval(this.statsTimer);
      this.statsTimer = -1;
    }
  }

  private async ensureNotificationPermission(): Promise<void> {
    try {
      if (notificationManager.isNotificationEnabledSync()) return;
      const context = getContext(this) as common.UIAbilityContext;
      await notificationManager.requestEnableNotification(context);
    } catch (e) {
      hilog.warn(DOMAIN_ID, TAG, 'notification permission: %{public}s', JSON.stringify(e));
    }
  }

  private updateProbe(index: number, outcome: ProbeOutcome): void {
    const next = this.probes.slice();
    next[index] = { name: next[index].name, done: true, ok: outcome.ok, detail: outcome.detail };
    this.probes = next;
  }

  private async runProbes(): Promise<void> {
    if (this.testing) return;
    this.testing = true;
    this.probes = [
      { name: 'DNS 解析', done: false, ok: false, detail: '测试中…' },
      { name: 'github.com', done: false, ok: false, detail: '测试中…' },
      { name: 'api.github.com', done: false, ok: false, detail: '测试中…' },
    ];
    try {
      await Promise.all([
        ConnectivityTest.probeDns('github.com').then((r: ProbeOutcome) => this.updateProbe(0, r)),
        ConnectivityTest.probeHttp('https://github.com/').then((r: ProbeOutcome) => this.updateProbe(1, r)),
        ConnectivityTest.probeHttp('https://api.github.com/').then((r: ProbeOutcome) => this.updateProbe(2, r)),
      ]);
    } catch (e) {
      hilog.error(DOMAIN_ID, TAG, 'probes failed: %{public}s', JSON.stringify(e));
    } finally {
      this.testing = false;
    }
  }

  private startVpn(): void {
    this.ensureNotificationPermission().finally(() => {
      this.launchVpn();
    });
  }

  private launchVpn(): void {
    const want: Want = {
      bundleName: 'com.biu.app',
      abilityName: 'BiuVpnExtAbility',
    };

    vpnExtension.startVpnExtensionAbility(want).then(() => {
      hilog.info(DOMAIN_ID, TAG, 'VPN started');
      this.isRunning = true;
      this.statusText = '加速中';
      this.startStatsPolling();
      setTimeout(() => {
        this.runProbes();
      }, 1500);
    }).catch((err: Error) => {
      hilog.error(DOMAIN_ID, TAG, 'VPN start failed: %{public}s', JSON.stringify(err));
      this.statusText = '启动失败';
    });
  }

  private stopVpn(): void {
    const want: Want = {
      bundleName: 'com.biu.app',
      abilityName: 'BiuVpnExtAbility',
    };

    vpnExtension.stopVpnExtensionAbility(want).then(() => {
      hilog.info(DOMAIN_ID, TAG, 'VPN stopped');
      this.isRunning = false;
      this.statusText = '已停止';
      this.stopStatsPolling();
    }).catch((err: Error) => {
      hilog.error(DOMAIN_ID, TAG, 'VPN stop failed: %{public}s', JSON.stringify(err));
    });
  }

  build() {
    Scroll() {
      Column() {
        Text('Biu')
          .fontSize(36)
          .fontWeight(FontWeight.Bold)
          .fontColor($r('app.color.primary_color'))
          .margin({ top: 60, bottom: 8 })

        Text('GitHub 加速 · HarmonyOS')
          .fontSize(14)
          .fontColor($r('app.color.text_secondary'))
          .margin({ bottom: 48 })

        Row() {
          Circle()
            .width(16)
            .height(16)
            .fill(this.isRunning ? $r('app.color.success_color') : $r('app.color.text_tertiary'))
            .margin({ right: 8 })
          Text(this.statusText)
            .fontSize(18)
            .fontColor(this.isRunning ? $r('app.color.success_color') : $r('app.color.text_secondary'))
        }
        .width(160)
        .height(56)
        .borderRadius(28)
        .backgroundColor($r('app.color.card_bg'))
        .justifyContent(FlexAlign.Center)
        .margin({ bottom: 32 })

        Button(this.isRunning ? '停止加速' : '一键加速')
          .width(240)
          .height(52)
          .fontSize(18)
          .fontWeight(FontWeight.Medium)
          .backgroundColor(this.isRunning ? $r('app.color.danger_color') : $r('app.color.primary_color'))
          .borderRadius(26)
          .onClick(() => {
            if (this.isRunning) {
              this.stopVpn();
            } else {
              this.startVpn();
            }
          })
          .margin({ bottom: 40 })

        Row() {
          StatCard({ label: 'DNS 请求', value: this.dnsQueries.toString() })
          StatCard({ label: '已加速', value: this.acceleratedQueries.toString() })
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceEvenly)
        .margin({ bottom: 24 })

        Column() {
          Row() {
            Text('连通性测试')
              .fontSize(14)
              .fontWeight(FontWeight.Medium)
              .fontColor($r('app.color.text_primary'))
            Blank()
            Button(this.testing ? '测试中…' : '立即测试')
              .height(28)
              .fontSize(12)
              .fontWeight(FontWeight.Medium)
              .backgroundColor($r('app.color.primary_color'))
              .borderRadius(14)
              .padding({ left: 14, right: 14 })
              .enabled(!this.testing)
              .onClick(() => {
                this.runProbes();
              })
          }
          .width('100%')
          .margin({ bottom: 8 })

          ForEach(this.probes, (probe: ProbeRow) => {
            Row() {
              Circle()
                .width(8)
                .height(8)
                .fill(probe.done
                  ? (probe.ok ? $r('app.color.success_color') : $r('app.color.danger_color'))
                  : $r('app.color.dot_off'))
                .margin({ right: 8 })
              Text(probe.name)
                .fontSize(13)
                .fontColor($r('app.color.text_primary'))
              Blank()
              Text(probe.detail)
                .fontSize(12)
                .fontColor(probe.done
                  ? (probe.ok ? $r('app.color.text_secondary') : $r('app.color.danger_color'))
                  : $r('app.color.text_tertiary'))
            }
            .width('100%')
            .height(30)
          }, (probe: ProbeRow) => `${probe.name}:${probe.detail}`)
        }
        .width('90%')
        .padding(16)
        .borderRadius(12)
        .backgroundColor($r('app.color.card_bg'))
        .alignItems(HorizontalAlign.Start)
        .margin({ bottom: 16 })

        Column() {
          Text('加速域名')
            .fontSize(14)
            .fontWeight(FontWeight.Medium)
            .fontColor($r('app.color.text_primary'))
            .margin({ bottom: 12 })

          ForEach(GITHUB_DOMAINS.slice(0, 6), (domain: string) => {
            Text(domain)
              .fontSize(12)
              .fontColor($r('app.color.text_secondary'))
              .margin({ bottom: 4 })
          })

          Text(`共 ${GITHUB_DOMAINS.length} 个域名`)
            .fontSize(12)
            .fontColor($r('app.color.text_tertiary'))
            .margin({ top: 4 })
        }
        .width('90%')
        .padding(16)
        .borderRadius(12)
        .backgroundColor($r('app.color.card_bg'))
        .alignItems(HorizontalAlign.Start)

        Text('本地 VPN 转发 · 数据不出设备')
          .fontSize(11)
          .fontColor($r('app.color.text_tertiary'))
          .margin({ top: 24, bottom: 24 })
      }
      .width('100%')
      .padding({ left: 24, right: 24 })
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.page_bg'))
    .align(Alignment.Top)
    .scrollBar(BarState.Off)
    .edgeEffect(EdgeEffect.Spring)
  }
}

@Component
struct StatCard {
  @Prop label: string;
  @Prop value: string;

  build() {
    Column() {
      Text(this.value)
        .fontSize(28)
        .fontWeight(FontWeight.Bold)
        .fontColor($r('app.color.text_primary'))
      Text(this.label)
        .fontSize(12)
        .fontColor($r('app.color.text_secondary'))
        .margin({ top: 4 })
    }
    .width(140)
    .height(80)
    .borderRadius(12)
    .backgroundColor($r('app.color.card_bg'))
    .justifyContent(FlexAlign.Center)
  }
}