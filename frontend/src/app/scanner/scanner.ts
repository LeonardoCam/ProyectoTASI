import { Component, ChangeDetectorRef } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { ScannerService, ScanResponse } from './scanner.service';

type Level = 'BAJO' | 'MEDIO' | 'ALTO';

/** Una búsqueda de esta sesión. Vive solo en memoria: se borra al recargar la página. */
export interface HistoryItem {
  url: string;              // lo que escribió el usuario
  finalUrl: string | null;  // destino real (null si hubo error)
  score: number | null;     // 0-100 = porcentaje de riesgo
  level: Level | null;
  at: Date;
  cached: boolean;
  error?: string;
}

const MAX_HISTORY = 20;

@Component({
  selector: 'app-scanner',
  standalone: true,
  imports: [FormsModule, DatePipe],
  templateUrl: './scanner.html',
  styleUrls: ['./scanner.css'],
})
export class ScannerComponent {
  inputUrl = '';
  result: ScanResponse | null = null;
  isLoading = false;
  errorMessage = '';
  history: HistoryItem[] = [];

  constructor(private scannerService: ScannerService, private cdr: ChangeDetectorRef) {}

  analyzeUrl() {
    const url = this.inputUrl.trim();
    if (!url || this.isLoading) return;

    this.isLoading = true;
    this.errorMessage = '';
    this.result = null;

    this.scannerService.scanUrl(url).subscribe({
      next: (data) => {
        this.result = data;
        this.isLoading = false;
        this.addToHistory({
          url, finalUrl: data.final_url, score: data.risk_score, level: data.risk_level,
          at: new Date(), cached: data.cached,
        });
        this.cdr.detectChanges();
      },
      error: (err: HttpErrorResponse) => {
        this.errorMessage = this.extractError(err);
        this.isLoading = false;
        this.addToHistory({
          url, finalUrl: null, score: null, level: null, at: new Date(), cached: false, error: this.errorMessage,
        });
        this.cdr.detectChanges();
      },
    });
  }

  private extractError(err: HttpErrorResponse): string {
    const detail = err.error?.detail;
    if (typeof detail === 'string') return detail;
    if (detail?.message) return detail.message;
    if (Array.isArray(detail)) return 'La URL ingresada no es válida.';
    return 'No se pudo conectar con el motor heurístico.';
  }

  getRiskColor(level: string): string {
    switch (level) {
      case 'ALTO': return '#ef4444';
      case 'MEDIO': return '#eab308';
      case 'BAJO': return '#22c55e';
      default: return '#6b7280';
    }
  }

  /** Agrega al inicio; si el enlace ya estaba, lo mueve arriba en vez de duplicarlo. */
  addToHistory(item: HistoryItem): void {
    this.history = [item, ...this.history.filter((h) => h.url !== item.url)].slice(0, MAX_HISTORY);
  }

  reanalyze(item: HistoryItem): void {
    this.inputUrl = item.url;
    this.analyzeUrl();
  }

  clearHistory(): void {
    this.history = [];
  }

  minutes(seconds: number): string {
    const m = Math.max(1, Math.round((seconds || 0) / 60));
    return m === 1 ? '1 minuto' : `${m} minutos`;
  }

  hasFactor(r: ScanResponse, id: string): boolean {
    return r.factors.some((f) => f.id === id);
  }

  threatText(r: ScanResponse): string {
    const ti = r.threat_intel;
    if (!ti || !ti.lists_loaded) return 'No disponibles';
    if (!ti.matches.length) return `Sin coincidencias (${ti.lists_loaded} listas consultadas)`;
    const kinds = [...new Set(ti.matches.map((m) => m.category))].join(' y ');
    return `Reportado como ${kinds} en ${ti.matches.map((m) => m.source).join(', ')}`;
  }

  /** Semáforo: devuelve true si la luz de ese nivel debe estar encendida. */
  isLit(light: Level): boolean {
    return this.result?.risk_level === light;
  }

  recommendation(level: Level): string {
    switch (level) {
      case 'ALTO': return 'No ingreses al enlace ni compartas datos. Es muy probable que sea fraudulento.';
      case 'MEDIO': return 'Procede con precaución: verifica el remitente y no ingreses credenciales.';
      default: return 'No se detectaron señales de riesgo relevantes, pero mantén la precaución habitual.';
    }
  }
}
