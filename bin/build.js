import { rmSync, unlinkSync, existsSync, readdirSync, lstatSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

function clearDirectory(dirPath) {
  if (existsSync(dirPath)) {
    readdirSync(dirPath).forEach(file => {
      const filePath = join(dirPath, file);
      if (lstatSync(filePath).isDirectory()) {
        rmSync(filePath, { recursive: true, force: true });
      } else {
        unlinkSync(filePath);
      }
    });
  }
}

// Clear the pkg folder
clearDirectory('pkg');

// Run wasm-pack build
execSync('wasm-pack build --target web --out-dir pkg --release', { stdio: 'inherit' });

// Remove specific files
unlinkSync('pkg/.gitignore');
unlinkSync('pkg/package.json');
unlinkSync('pkg/README.md');