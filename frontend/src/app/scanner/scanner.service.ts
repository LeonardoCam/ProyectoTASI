import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface RiskFactor {
  id: string;
  description: string;
  points: number;
}

export interface ScanResponse {
  input_url: string;
  original_url: string;
  final_url: string;
  defanged_url?: string;
  redirect_chain: string[];
  chain_details?: {
    hop: number;
    url: string;
    status_code?: number;
    domain: string;
    https: boolean;
    cross_domain: boolean;
  }[];
  url_components?: {
    scheme: string;
    subdomain: string | null;
    domain: string | null;
    tld: string | null;
    registered_domain: string;
    port: number | null;
    path: string;
    query: string | null;
    fragment: string | null;
  };
  hops: number;
  https: boolean;
  domain: string;
  registered_domain: string;
  domain_age_days: number | null;
  cert_age_days?: number | null;
  page_title?: string | null;
  security_headers?: Record<string, boolean>;
  domain_exists: boolean;
  reachable: boolean;
  dns_note: string | null;
  reputation_checked: boolean;
  risk_score: number;
  risk_level: 'BAJO' | 'MEDIO' | 'ALTO';
  factors: RiskFactor[];
  ml_analysis?: {
    available: boolean;
    probability: number | null;
    risk_score: number | null;
    risk_level: string;
    calibrated_grey_zone: boolean;
  };
  threat_intel: {
    destination_visited: boolean;
    lists_loaded: number;
    matches: { source: string; category: 'malware' | 'phishing'; matched: string }[];
    virustotal: { malicious: number; suspicious: number; engines: number; link: string } | null;
  };
  cached: boolean;
  analyzed_at: string;
  cache_expires_in_s: number;
  elapsed_ms: number;
}

@Injectable({ providedIn: 'root' })
export class ScannerService {
  private apiUrl = `${environment.apiUrl}/expand`;

  constructor(private http: HttpClient) {}

  scanUrl(url: string): Observable<ScanResponse> {
    return this.http.post<ScanResponse>(this.apiUrl, { url });
  }

  sendFeedback(url: string, feedbackType: string, comment?: string): Observable<any> {
    const feedbackUrl = `${environment.apiUrl}/feedback`;
    return this.http.post(feedbackUrl, { url, feedback_type: feedbackType, comment });
  }
}
