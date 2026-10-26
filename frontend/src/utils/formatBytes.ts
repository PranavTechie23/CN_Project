/**
 * Format bytes into human-readable units (B, KB, MB, GB, TB).
 */
export function formatBytes(bytes: number, decimals = 1): string {
  if (!bytes || bytes <= 0) return '0 B';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const safeI = Math.min(i, sizes.length - 1);

  return `${parseFloat((bytes / Math.pow(k, safeI)).toFixed(dm))} ${sizes[safeI]}`;
}

/**
 * Format bytes per second into rate string (e.g. "124 KB/s").
 */
export function formatRate(bytesPerSec: number, decimals = 1): string {
  return `${formatBytes(bytesPerSec, decimals)}/s`;
}
