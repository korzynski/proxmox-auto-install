import { readFile } from 'node:fs/promises';

export default async (request, context) => {
  // Resolve the file two levels up from this file (repo root)
  const fileUrl = new URL('../../answer.toml', import.meta.url);
  const body = await readFile(fileUrl, 'utf8');

  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store'
    }
  });
};

