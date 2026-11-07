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
  original_url: string;
  final_url: string;
  redirect_chain: string[];
  hops: number;
  https: boolean;
  domain: string;
  registered_domain: string;
  domain_age_days: number | null;
  reputation_checked: boolean;
  risk_score: number;
  risk_level: 'BAJO' | 'MEDIO' | 'ALTO';
  factors: RiskFactor[];
  cached: boolean;
  elapsed_ms: number;
}

@Injectable({ providedIn: 'root' })
export class ScannerService {
  private apiUrl = `${environment.apiUrl}/expand`;

  constructor(private http: HttpClient) {}

  scanUrl(url: string): Observable<ScanResponse> {
    return this.http.post<ScanResponse>(this.apiUrl, { url });
  }
}
