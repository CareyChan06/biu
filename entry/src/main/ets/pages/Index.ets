import { vpnExtension } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import biu from 'libbiu.so';

const TAG = 'BiuUI';
const DOMAIN_ID = 0x0000;

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
  private statsTimer: number = -1;

  aboutToDisappear(): void {
    this.stopStatsPolling();
  }

  private startStatsPolling(): void {
    this.statsTimer = setInterval(() => {
      try {
        const stats = biu.getStats();
        this.isRunning = stats.running;
        this.dnsQueries = stats.dnsQueries;
        this.acceleratedQueries = stats.acceleratedQueries;
        if (stats.running) {
          this.statusText = '加速中';
        }
      } catch (e) {
        hilog.error(DOMAIN_ID, TAG, 'getStats error: %{public}s', JSON.stringify(e));
      }
    }, 1000);
  }

  private stopStatsPolling(): void {
    if (this.statsTimer !== -1) {
      clearInterval(this.statsTimer);
      this.statsTimer = -1;
    }
  }

  private startVpn(): void {
    biu.setDomains(GITHUB_DOMAINS);

    const want: Want = {
      bundleName: 'com.biu.app',
      abilityName: 'BiuVpnExtAbility',
    };

    vpnExtension.startVpnExtensionAbility(want).then(() => {
      hilog.info(DOMAIN_ID, TAG, 'VPN started');
      this.isRunning = true;
      this.statusText = '加速中';
      this.startStatsPolling();
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
    Column() {
      Text('Biu')
        .fontSize(36)
        .fontWeight(FontWeight.Bold)
        .fontColor('#0A59F7')
        .margin({ top: 60, bottom: 8 })

      Text('GitHub 加速 · HarmonyOS')
        .fontSize(14)
        .fontColor('#999')
        .margin({ bottom: 48 })

      Row() {
        Circle()
          .width(16)
          .height(16)
          .fill(this.isRunning ? '#00B42A' : '#C9CDD4')
          .margin({ right: 8 })
        Text(this.statusText)
          .fontSize(18)
          .fontColor(this.isRunning ? '#00B42A' : '#86909C')
      }
      .width(160)
      .height(56)
      .borderRadius(28)
      .backgroundColor('#F7F8FA')
      .justifyContent(FlexAlign.Center)
      .margin({ bottom: 32 })

      Button(this.isRunning ? '停止加速' : '一键加速')
        .width(240)
        .height(52)
        .fontSize(18)
        .fontWeight(FontWeight.Medium)
        .backgroundColor(this.isRunning ? '#F53F3F' : '#0A59F7')
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
        this.StatCard('DNS 请求', this.dnsQueries.toString())
        this.StatCard('已加速', this.acceleratedQueries.toString())
      }
      .width('100%')
      .justifyContent(FlexAlign.SpaceEvenly)
      .margin({ bottom: 32 })

      Column() {
        Text('加速域名')
          .fontSize(14)
          .fontWeight(FontWeight.Medium)
          .fontColor('#1D2129')
          .margin({ bottom: 12 })

        ForEach(GITHUB_DOMAINS.slice(0, 6), (domain: string) => {
          Text(domain)
            .fontSize(12)
            .fontColor('#86909C')
            .margin({ bottom: 4 })
        })

        Text(`共 ${GITHUB_DOMAINS.length} 个域名`)
          .fontSize(12)
          .fontColor('#C9CDD4')
          .margin({ top: 4 })
      }
      .width('90%')
      .padding(16)
      .borderRadius(12)
      .backgroundColor('#F7F8FA')
      .alignItems(HorizontalAlign.Start)

      Blank()

      Text('本地 VPN DNS 优化 · 不改变系统路由')
        .fontSize(11)
        .fontColor('#C9CDD4')
        .margin({ bottom: 24 })
    }
    .width('100%')
    .height('100%')
    .padding({ left: 24, right: 24 })
    .backgroundColor('#FFFFFF')
  }

  @Builder
  StatCard(label: string, value: string) {
    Column() {
      Text(value)
        .fontSize(28)
        .fontWeight(FontWeight.Bold)
        .fontColor('#1D2129')
      Text(label)
        .fontSize(12)
        .fontColor('#86909C')
        .margin({ top: 4 })
    }
    .width(140)
    .height(80)
    .borderRadius(12)
    .backgroundColor('#F7F8FA')
    .justifyContent(FlexAlign.Center)
  }
}