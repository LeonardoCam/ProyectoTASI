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

  it('keeps a deduplicated, capped history with the newest first', () => {
    const c = TestBed.createComponent(ScannerComponent).componentInstance;
    const item = (url: string, score: number) =>
      ({ url, finalUrl: url, score, level: 'BAJO', at: new Date(), cached: false }) as const;
    c.addToHistory(item('a.com', 10));
    c.addToHistory(item('b.com', 40));
    c.addToHistory(item('a.com', 15));               // repetido: sube al inicio, sin duplicar
    expect(c.history.map((h) => h.url)).toEqual(['a.com', 'b.com']);
    expect(c.history[0].score).toBe(15);
    for (let i = 0; i < 30; i++) c.addToHistory(item(`s${i}.com`, i));
    expect(c.history.length).toBe(20);
    c.clearHistory();
    expect(c.history).toEqual([]);
  });

  it('extracts structured API errors', () => {
    const c = TestBed.createComponent(ScannerComponent).componentInstance as any;
    const msg = c.extractError({ error: { detail: { code: 'blocked_address', message: 'Destino bloqueado' } } });
    expect(msg).toBe('Destino bloqueado');
  });
});
