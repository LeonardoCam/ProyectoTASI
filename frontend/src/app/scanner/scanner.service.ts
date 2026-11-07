import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface ScanResponse {
  original_url: string;
  final_url: string;
  redirect_chain: string[];
  domain: string;
  domain_age_days: number | null;
  risk_level: string;
}

@Injectable({
  providedIn: 'root'
})
export class ScannerService {
  private apiUrl = 'http://127.0.0.1:8000/api/v1/expand';

  constructor(private http: HttpClient) {}

  scanUrl(url: string): Observable<ScanResponse> {
    return this.http.post<ScanResponse>(this.apiUrl, { url });
  }
}