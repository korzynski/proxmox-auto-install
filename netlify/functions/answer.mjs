import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Path to the file at the site root
const ANSWER_PATH = join(__dirname, '..', '..', 'answer.toml');

export default async (request, context) => {
  const body = await readFile(ANSWER_PATH, 'utf8');
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store'
    }
  });
};
