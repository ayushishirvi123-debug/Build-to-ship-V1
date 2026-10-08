import axios from 'axios';

const base = import.meta.env.VITE_API_URL || '';
export const apiBase = base || window.location.origin;

export const api = axios.create({ baseURL: base, validateStatus: (s) => s < 500 });
api.interceptors.request.use((c) => {
  const t = localStorage.getItem('ps_token');
  if (t) c.headers.Authorization = 'Bearer ' + t;
  return c;
});
api.interceptors.response.use((r) => {
  if (r.status === 401 && !r.config.url.includes('/auth/')) {
    localStorage.removeItem('ps_token');
    window.location.href = '/login';
  }
  return r;
});

export async function download(path, filename) {
  const r = await api.get(path, { responseType: 'blob' });
  const url = URL.createObjectURL(r.data);
  const a = Object.assign(document.createElement('a'), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}
