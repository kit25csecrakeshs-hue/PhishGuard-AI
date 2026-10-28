import dns from 'dns';
import type { DnsInfo } from '../src/types.js';

const dnsPromises = dns.promises;

/**
 * Checks whether an IP address belongs to private, loopback, or link-local ranges (SSRF defense)
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip) return false;

  // IPv4 Loopback (127.0.0.0/8)
  if (ip.startsWith('127.')) return true;

  // IPv4 Private Networks (RFC 1918)
  if (ip.startsWith('10.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith('192.168.')) return true;

  // Link-local (169.254.0.0/16)
  if (ip.startsWith('169.254.')) return true;

  // Current network / Broadcast
  if (ip === '0.0.0.0' || ip === '255.255.255.255') return true;

  // IPv6 loopback & link-local
  if (ip === '::1' || ip === '::' || ip.toLowerCase().startsWith('fe80:') || ip.toLowerCase().startsWith('fc00:')) {
    return true;
  }

  return false;
}

/**
 * Performs DNS resolution for IPv4, IPv6, and NS records safely with SSRF screening
 */
export async function lookupDnsAndIp(domain: string): Promise<DnsInfo> {
  const result: DnsInfo = {
    ipv4: [],
    ipv6: [],
    nameservers: [],
    hostname: domain,
    dnssec: false,
    is_private_ip: false,
  };

  // If input is directly an IP
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
    result.ipv4 = [domain];
    result.is_private_ip = isPrivateOrReservedIp(domain);
    return result;
  }

  // Resolve A records (IPv4)
  try {
    const aRecords = await Promise.race([
      dnsPromises.resolve4(domain),
      new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000)),
    ]);
    result.ipv4 = aRecords;
    if (aRecords.some(isPrivateOrReservedIp)) {
      result.is_private_ip = true;
    }
  } catch {
    // DNS A resolution failed or timed out
  }

  // Resolve AAAA records (IPv6)
  try {
    const aaaaRecords = await Promise.race([
      dnsPromises.resolve6(domain),
      new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000)),
    ]);
    result.ipv6 = aaaaRecords;
    if (aaaaRecords.some(isPrivateOrReservedIp)) {
      result.is_private_ip = true;
    }
  } catch {
    // DNS AAAA resolution failed or timed out
  }

  // Resolve NS records
  try {
    const nsRecords = await Promise.race([
      dnsPromises.resolveNs(domain),
      new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000)),
    ]);
    result.nameservers = nsRecords;
  } catch {
    // DNS NS resolution failed
  }

  return result;
}
