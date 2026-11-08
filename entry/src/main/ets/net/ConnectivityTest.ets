import { connection, http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

const TAG = 'BiuConn';
const DOMAIN_ID = 0x0000;
const TIMEOUT_MS = 5000;

export interface ProbeOutcome {
  ok: boolean;
  detail: string;
}

export class ConnectivityTest {
  static async probeDns(host: string): Promise<ProbeOutcome> {
    const start = Date.now();
    try {
      const addresses = await connection.getAddressesByName(host);
      const ms = Date.now() - start;
      if (addresses.length === 0) {
        return { ok: false, detail: '无解析结果' };
      }
      return { ok: true, detail: `${addresses[0].address} · ${ms} ms` };
    } catch (e) {
      hilog.warn(DOMAIN_ID, TAG, 'dns probe failed: %{public}s', JSON.stringify(e));
      return { ok: false, detail: '解析失败' };
    }
  }

  static async probeHttp(url: string): Promise<ProbeOutcome> {
    let outcome = await ConnectivityTest.requestOnce(url);
    if (!outcome.ok) {
      outcome = await ConnectivityTest.requestOnce(url);
    }
    return outcome;
  }

  private static async requestOnce(url: string): Promise<ProbeOutcome> {
    const start = Date.now();
    const client = http.createHttp();
    try {
      const response = await client.request(url, {
        method: http.RequestMethod.HEAD,
        connectTimeout: TIMEOUT_MS,
        readTimeout: TIMEOUT_MS,
        usingCache: false
      });
      const ms = Date.now() - start;
      const code = response.responseCode;
      if (code >= 200 && code < 400) {
        return { ok: true, detail: `${ms} ms` };
      }
      return { ok: false, detail: `HTTP ${code}` };
    } catch (e) {
      const code = (e as BusinessError).code;
      hilog.warn(DOMAIN_ID, TAG, 'http probe failed: %{public}s', JSON.stringify(e));
      return { ok: false, detail: code === 2300028 ? '超时' : `失败 ${code}` };
    } finally {
      client.destroy();
    }
  }
}
