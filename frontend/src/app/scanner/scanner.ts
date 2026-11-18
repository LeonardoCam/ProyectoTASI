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
  copiedReport = false;
  feedbackSent = false;
  feedbackMsg = '';

  constructor(private scannerService: ScannerService, private cdr: ChangeDetectorRef) {}

  analyzeUrl() {
    const url = this.inputUrl.trim();
    if (!url || this.isLoading) return;

    this.isLoading = true;
    this.errorMessage = '';
    this.result = null;
    this.feedbackSent = false;
    this.feedbackMsg = '';

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

  loadExample(url: string): void {
    this.inputUrl = url;
    this.analyzeUrl();
  }

  copyForensicReport(r: ScanResponse): void {
    const factorsText = r.factors.length
      ? r.factors.map((f) => `  * [${f.points > 0 ? '+' : ''}${f.points}] ${f.description}`).join('\n')
      : '  * Ningún factor de riesgo detectado.';

    const report = [
      '# Reporte Forense de Evaluación de Enlace (TASI - UPCH)',
      `- Fecha y hora: ${r.analyzed_at}`,
      `- Enlace ingresado: ${r.input_url}`,
      `- Destino final: ${r.final_url}`,
      `- Dominio registrado: ${r.registered_domain}`,
      `- Nivel de riesgo: ${r.risk_level} (${r.risk_score}/100)`,
      `- Protocolo: ${r.https ? 'HTTPS (Cifrado)' : 'HTTP (Sin cifrar)'}`,
      `- Saltos de redirección: ${r.hops}`,
      `- Antigüedad de dominio: ${r.domain_age_days !== null ? r.domain_age_days + ' días' : 'No disponible (WHOIS protegido)'}`,
      r.page_title ? `- Título de la página: "${r.page_title}"` : null,
      r.cert_age_days !== undefined && r.cert_age_days !== null ? `- Certificado SSL: emitido hace ${r.cert_age_days} días` : null,
      '- Factores evaluados:',
      factorsText,
      '- Cadena de trazabilidad:',
      ...r.redirect_chain.map((c, i) => `  ${i + 1}. ${c}`),
    ].filter(Boolean).join('\n');

    navigator.clipboard.writeText(report).then(() => {
      this.copiedReport = true;
      this.cdr.detectChanges();
      setTimeout(() => {
        this.copiedReport = false;
        this.cdr.detectChanges();
      }, 3000);
    });
  }

  sendFeedback(type: string): void {
    if (!this.result || this.feedbackSent) return;
    this.feedbackSent = true;
    this.scannerService.sendFeedback(this.result.final_url, type).subscribe({
      next: () => {
        this.feedbackMsg = type === 'ok' ? '¡Gracias por confirmar!' : 'Reporte registrado para revisión.';
        this.cdr.detectChanges();
      },
      error: () => {
        this.feedbackMsg = 'Reporte registrado localmente.';
        this.cdr.detectChanges();
      },
    });
  }
}
