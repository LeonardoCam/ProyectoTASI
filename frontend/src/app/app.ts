import { Component } from '@angular/core';
import { ScannerComponent } from './scanner/scanner'; 

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [ScannerComponent], 
  templateUrl: './app.html',
  styleUrls: ['./app.css']
})
export class App {
  title = 'frontend';
}