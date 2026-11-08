export const startTun: (tunFd: number) => void;
export const stopTun: () => void;
export const setDomains: (domains: string[]) => void;
export const setStatsPath: (path: string) => void;
export const getStats: () => TunStats;

export interface TunStats {
  running: boolean;
  dnsQueries: number;
  acceleratedQueries: number;
}