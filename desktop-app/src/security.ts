export function isAllowedDesktopRequest(host: string | undefined, origin: string | undefined, port: number): boolean {
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const allowedOrigins = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
  return !!host && allowedHosts.has(host) && (!origin || allowedOrigins.has(origin));
}
