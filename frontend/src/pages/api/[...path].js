const api = process.env.API_BASE_URL || 'http://localhost:3001';

async function proxy(context) {
  const url = new URL(context.request.url);
  const target = `${api}/api${url.pathname.replace(/^\/api/, '')}${url.search}`;
  const headers = new Headers();
  const contentType = context.request.headers.get('content-type');
  if (contentType) headers.set('content-type', contentType);
  const response = await fetch(target, {
    method: context.request.method,
    headers,
    body: ['GET', 'HEAD'].includes(context.request.method) ? undefined : await context.request.text(),
    signal: AbortSignal.timeout(65000)
  });
  return new Response(response.body, { status: response.status, headers: { 'content-type': response.headers.get('content-type') || 'application/json' } });
}

export const GET = proxy;
export const POST = proxy;
