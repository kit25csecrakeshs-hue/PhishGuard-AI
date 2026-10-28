import type { DomainInfo } from '../src/types.js';

/**
 * Calculates domain age in days given an ISO or RFC date string
 */
export function calculateDomainAgeDays(creationDateStr: string | null): number | null {
  if (!creationDateStr) return null;
  try {
    const created = new Date(creationDateStr);
    if (isNaN(created.getTime())) return null;
    const now = new Date();
    const diffMs = now.getTime() - created.getTime();
    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    return days >= 0 ? days : null;
  } catch {
    return null;
  }
}

/**
 * Performs RDAP (Registration Data Access Protocol) query for domain metadata
 * Includes timeout and safe defaults for local/internal domains.
 */
export function lookupDomainRDAP(domain: string): Promise<DomainInfo> {
  return new Promise(async (resolve) => {
    // Basic validation & bypass for IPs and localhost
    if (!domain || domain === 'localhost' || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      return resolve({
        domain,
        creation_date: null,
        expiration_date: null,
        updated_date: null,
        registrar: null,
        registrar_id: null,
        registrant_name: null,
        organization: null,
        country: null,
        privacy_protected: false,
        domain_status: ['local_or_ip_host'],
        abuse_contact: null,
      });
    }

    // Try RDAP bootstrap endpoint with 3-second timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    try {
      // Use public RDAP gateway
      const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
        signal: controller.signal,
        headers: {
          'Accept': 'application/rdap+json, application/json',
          'User-Agent': 'PhishGuard-AI/1.0',
        },
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        return resolve(fallbackDomainInfo(domain));
      }

      const data = await res.json();

      let creationDate: string | null = null;
      let expirationDate: string | null = null;
      let updatedDate: string | null = null;

      if (Array.isArray(data.events)) {
        for (const evt of data.events) {
          if (evt.eventAction === 'registration') creationDate = evt.eventDate;
          if (evt.eventAction === 'expiration') expirationDate = evt.eventDate;
          if (evt.eventAction === 'last changed' || evt.eventAction === 'last update') updatedDate = evt.eventDate;
        }
      }

      // Check registrar and entities
      let registrar: string | null = null;
      let registrarId: string | null = null;
      let org: string | null = null;
      let country: string | null = null;
      let abuseContact: string | null = null;
      let privacyProtected = false;

      if (Array.isArray(data.entities)) {
        for (const ent of data.entities) {
          const roles = ent.roles || [];
          if (roles.includes('registrar')) {
            registrar = ent.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || ent.handle || null;
            registrarId = ent.publicIds?.[0]?.identifier || null;
          }
          if (roles.includes('registrant')) {
            const fn = ent.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3];
            org = ent.vcardArray?.[1]?.find((v: any) => v[0] === 'org')?.[3] || null;
            if (fn && /privacy|protect|whoisguard|redacted|proxy/i.test(fn)) {
              privacyProtected = true;
            }
          }
          if (roles.includes('abuse')) {
            abuseContact = ent.vcardArray?.[1]?.find((v: any) => v[0] === 'email')?.[3] || null;
          }
        }
      }

      const status = Array.isArray(data.status) ? data.status : ['active'];

      resolve({
        domain,
        creation_date: creationDate,
        expiration_date: expirationDate,
        updated_date: updatedDate,
        registrar,
        registrar_id: registrarId,
        registrant_name: privacyProtected ? 'Redacted for Privacy' : null,
        organization: org,
        country,
        privacy_protected: privacyProtected,
        domain_status: status,
        abuse_contact: abuseContact,
      });
    } catch {
      clearTimeout(timeoutId);
      resolve(fallbackDomainInfo(domain));
    }
  });
}

function fallbackDomainInfo(domain: string): DomainInfo {
  return {
    domain,
    creation_date: null,
    expiration_date: null,
    updated_date: null,
    registrar: null,
    registrar_id: null,
    registrant_name: null,
    organization: null,
    country: null,
    privacy_protected: false,
    domain_status: ['rdap_lookup_unavailable'],
    abuse_contact: null,
  };
}
