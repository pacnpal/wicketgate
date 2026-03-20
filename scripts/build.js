import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const srcPath = path.join(__dirname, '..', 'src', 'worker.js');
const htmlPath = path.join(__dirname, '..', 'src', 'dashboard.html');
const destDir = path.join(__dirname, '..', 'dist');
const destWorker = path.join(destDir, 'worker.js');
const destHtml = path.join(destDir, 'dashboard.html');

if (!fs.existsSync(destDir)) fs.mkdirSync(destDir);

// Copy dashboard HTML so the dist worker can import it (since wrangler.jsonc points there now)
if (fs.existsSync(htmlPath)) {
	fs.copyFileSync(htmlPath, destHtml);
}

let content = fs.readFileSync(srcPath, 'utf8');

const token = process.env.CF_API_TOKEN || '';
const account = process.env.CF_ACCOUNT_ID || '';

content = content.replace(/__INJECT_CF_API_TOKEN__/g, token);
content = content.replace(/__INJECT_CF_ACCOUNT_ID__/g, account);
content = content.replace(/from '\.\/dashboard\.html'/g, "from './dashboard.html'");

fs.writeFileSync(destWorker, content);
console.log('✅ Injected tokens into dist/worker.js');
