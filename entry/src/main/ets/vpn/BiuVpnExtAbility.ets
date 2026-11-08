import { VpnExtensionAbility, vpnExtension } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import biu from 'libbiu.so';

const TAG = 'BiuVPN';
const DOMAIN_ID = 0x0000;
const TUN_IP = '10.0.0.1';
const TUN_MTU = 1500;

export default class BiuVpnExtAbility extends VpnExtensionAbility {
  private vpnConnection: vpnExtension.VpnConnection | null = null;

  onCreate(want: Want): void {
    hilog.info(DOMAIN_ID, TAG, 'VpnExtensionAbility onCreate');
    hilog.info(DOMAIN_ID, TAG, 'ext filesDir: %{public}s', this.context.filesDir);
    biu.setStatsPath(`${this.context.filesDir}/biu_stats.json`);
    this.setupVpn();
  }

  private async setupVpn(): Promise<void> {
    this.vpnConnection = vpnExtension.createVpnConnection(this.context);

    const config: vpnExtension.VpnConfig = {
      addresses: [
        {
          address: { address: TUN_IP, family: 1 },
          prefixLength: 24
        }
      ],
      mtu: TUN_MTU,
      dnsAddresses: [TUN_IP],
      routes: [
        {
          interface: 'vpn-tun',
          destination: {
            address: { address: '0.0.0.0', family: 1 },
            prefixLength: 0
          },
          gateway: {
            address: TUN_IP,
            family: 1
          },
          hasGateway: true,
          isDefaultRoute: true
        }
      ],
      isIPv4Accepted: true,
      isIPv6Accepted: false,
    };

    try {
      const tunFd = await this.vpnConnection.create(config);
      hilog.info(DOMAIN_ID, TAG, 'TUN created, fd=%{public}d', tunFd);

      await this.vpnConnection.protectProcessNet();
      hilog.info(DOMAIN_ID, TAG, 'Process net protected');

      biu.startTun(tunFd);
      hilog.info(DOMAIN_ID, TAG, 'TUN reader started');
    } catch (err) {
      hilog.error(DOMAIN_ID, TAG, 'VPN setup failed: %{public}s', JSON.stringify(err));
    }
  }

  onDestroy(): void {
    hilog.info(DOMAIN_ID, TAG, 'VpnExtensionAbility onDestroy');
    biu.stopTun();
    if (this.vpnConnection) {
      this.vpnConnection.destroy().then(() => {
        hilog.info(DOMAIN_ID, TAG, 'VPN destroyed');
      }).catch((err: Error) => {
        hilog.error(DOMAIN_ID, TAG, 'VPN destroy failed: %{public}s', JSON.stringify(err));
      });
      this.vpnConnection = null;
    }
  }
}