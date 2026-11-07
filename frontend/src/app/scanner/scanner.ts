import { Component, ChangeDetectorRef } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { ScannerService, ScanResponse } from './scanner.service';

type Level = 'BAJO' | 'MEDIO' | 'ALTO';

@Component({
  selector: 'app-scanner',
  standalone: true,
  imports: [FormsModule],
  templateUrl: './scanner.html',
  styleUrls: ['./scanner.css'],
})
export class ScannerComponent {
  inputUrl = '';
  result: ScanResponse | null = null;
  isLoading = false;
  errorMessage = '';

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
        this.cdr.detectChanges();
      },
      error: (err: HttpErrorResponse) => {
        this.errorMessage = this.extractError(err);
        this.isLoading = false;
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
