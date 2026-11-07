import { Component, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScannerService, ScanResponse } from './scanner.service';

@Component({
  selector: 'app-scanner',
  standalone: true,
  imports: [CommonModule, FormsModule], 
  templateUrl: './scanner.html',
  styleUrls: ['./scanner.css']
})
export class ScannerComponent { // Recuerda que si le cambiaste el nombre a 'Scanner' en lugar de 'ScannerComponent', mantenlo como lo tenías.
  inputUrl: string = '';
  result: ScanResponse | null = null;
  isLoading: boolean = false;
  errorMessage: string = '';

  constructor(
    private scannerService: ScannerService,
    private cdr: ChangeDetectorRef // 1. Inyectamos el detector de cambios
  ) {}

  analyzeUrl() {
    if (!this.inputUrl) return;
    
    this.isLoading = true;
    this.errorMessage = '';
    this.result = null;

    this.scannerService.scanUrl(this.inputUrl).subscribe({
      next: (data) => {
        this.result = data;
        this.isLoading = false;
        this.cdr.detectChanges(); // 2. Forzamos a Angular a pintar la pantalla INMEDIATAMENTE
      },
      error: (err) => {
        this.errorMessage = err.error?.detail || 'Error de red al conectar con el motor heurístico.';
        this.isLoading = false;
        this.cdr.detectChanges(); // 3. Forzamos a Angular a pintar la pantalla INMEDIATAMENTE
      }
    });
  }

  getRiskColor(risk: string): string {
    switch(risk) {
      case 'ALTO': return '#ef4444';
      case 'MEDIO': return '#eab308';
      case 'BAJO': return '#22c55e';
      default: return '#6b7280';
    }
  }
}