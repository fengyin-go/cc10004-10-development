/** 统一请求封装：拼后端地址、自动携带安全令牌、集中处理 401 与错误提示。 */
import { useSessionStore } from '@/stores/session'

const API_BASE = import.meta.env.VITE_API_BASE ?? ''

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function request(path: string, init?: RequestInit): Promise<Response> {
  const session = useSessionStore()
  const url = path.startsWith('http') ? path : `${API_BASE}${path}`
  const headers = new Headers(init?.headers)
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  if (session.token) {
    headers.set('Authorization', `Bearer ${session.token}`)
  }
  return fetch(url, { ...init, headers })
    .then(async (response) => {
      if (response.status === 401) {
        // 令牌失效：清理本地会话，交由登录页重新认证
        session.clear()
      }
      return response
    })
    .catch((error: unknown) => {
      const detail = error instanceof Error ? error.message : '请求未送达'
      throw new ApiError(0, `接口请求失败：${detail}`)
    })
}

/** 解析响应 JSON；非 2xx 时抛出带后端提示的 ApiError。 */
export async function readJson<T>(response: Response): Promise<T> {
  const data = (await response.json().catch(() => ({}))) as { detail?: unknown }
  if (!response.ok) {
    const detail = data.detail
    const message = Array.isArray(detail)
      ? '请求参数不合法，请检查输入'
      : typeof detail === 'string'
        ? detail
        : `接口返回 ${response.status}，操作未生效`
    throw new ApiError(response.status, message)
  }
  return data as T
}

export async function fetchJson<T>(path: string): Promise<T> {
  const response = await request(path)
  return readJson<T>(response)
}
