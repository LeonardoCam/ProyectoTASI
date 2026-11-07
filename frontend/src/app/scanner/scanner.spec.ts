import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { ScannerComponent } from './scanner';

describe('ScannerComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ScannerComponent],
      providers: [provideHttpClient()],
    }).compileComponents();
  });

  it('should create', () => {
    const fixture = TestBed.createComponent(ScannerComponent);
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('lights only the matching traffic light', () => {
    const c = TestBed.createComponent(ScannerComponent).componentInstance;
    c.result = { risk_level: 'MEDIO' } as any;
    expect(c.isLit('MEDIO')).toBe(true);
    expect(c.isLit('ALTO')).toBe(false);
    expect(c.isLit('BAJO')).toBe(false);
  });

  it('extracts structured API errors', () => {
    const c = TestBed.createComponent(ScannerComponent).componentInstance as any;
    const msg = c.extractError({ error: { detail: { code: 'blocked_address', message: 'Destino bloqueado' } } });
    expect(msg).toBe('Destino bloqueado');
  });
});
