/** Accept only an exact HTTPS Quick Tunnel origin, never an arbitrary log URL. */
export function phoneOrigin(output: string): string | undefined {
  return output.match(/https:\/\/[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com(?=[\s/|"']|$)/)?.[0];
}
