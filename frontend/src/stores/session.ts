import { defineStore } from 'pinia'

export type SessionUser = {
  username: string
  display_name: string
  disabled: boolean
}

const TOKEN_KEY = 'dio.security.token'
const USER_KEY = 'dio.security.user'

function readStoredUser(): SessionUser | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as SessionUser
  } catch {
    return null
  }
}

export const useSessionStore = defineStore('session', {
  state: () => ({
    token: localStorage.getItem(TOKEN_KEY) ?? '',
    user: readStoredUser(),
    operator: readStoredUser()?.display_name ?? '未登录',
    shiftLabel: '白班 08:00-20:00',
    scope: '数据洞察分析工作台',
  }),
  getters: {
    isAuthenticated: (state) => Boolean(state.token),
    canOperate: (state) => state.token.length > 0,
    username: (state) => state.user?.username ?? '',
  },
  actions: {
    setSession(token: string, user: SessionUser) {
      this.token = token
      this.user = user
      this.operator = user.display_name
      localStorage.setItem(TOKEN_KEY, token)
      localStorage.setItem(USER_KEY, JSON.stringify(user))
    },
    clear() {
      this.token = ''
      this.user = null
      this.operator = '未登录'
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(USER_KEY)
    },
    setShift(label: string) {
      this.shiftLabel = label
    },
  },
})
