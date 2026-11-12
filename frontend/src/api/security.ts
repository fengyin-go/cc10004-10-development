/** 受控连接安全子系统的接口类型与请求封装。 */
import { readJson, request } from '@/api/client'

export type SessionUser = {
  username: string
  display_name: string
  disabled: boolean
}

export type LoginResult = {
  token: string
  token_type: string
  user: SessionUser
}

export type ControlledConnection = {
  id: string
  name: string
  connection_type: string
  address: string
  credential: string
  owner: string
  is_owner: boolean
  credential_version: number
  address_version: number
  created_at: string
  updated_at: string
}

export type Delegation = {
  id: string
  connection_id: string
  dataset_code: string
  granter: string
  grantee: string
  status: string
  suspended_address_version: number | null
  created_at: string
  updated_at: string
}

export type Handover = {
  id: string
  connection_id: string
  from_owner: string
  to_owner: string
  status: string
  created_at: string
  decided_at: string | null
}

export type ConnectionHandle = {
  connection_id: string
  dataset_code: string
  connection_type: string
  endpoint: string
  credential_handle: string
  credential_version: number
  via: string
}

export type AuditEvent = {
  id: string
  at: string
  actor: string
  action: string
  connection_id: string | null
  dataset_code: string | null
  detail: string
}

const BASE = '/api/security'

async function post<T>(path: string, body?: unknown): Promise<T> {
  const response = await request(`${BASE}${path}`, {
    method: 'POST',
    body: JSON.stringify(body ?? {}),
  })
  return readJson<T>(response)
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const response = await request(`${BASE}${path}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  })
  return readJson<T>(response)
}

export const securityApi = {
  login: (username: string, password: string) =>
    post<LoginResult>('/auth/login', { username, password }),
  me: () => request(`${BASE}/auth/me`).then((r) => readJson<SessionUser>(r)),

  listConnections: () =>
    request(`${BASE}/connections`).then((r) =>
      readJson<{ items: ControlledConnection[] }>(r),
    ),
  createConnection: (payload: {
    name: string
    connection_type: string
    address: string
    credential: string
  }) => post<ControlledConnection>('/connections', payload),
  updateAddress: (connectionId: string, address: string) =>
    put<ControlledConnection>(`/connections/${connectionId}/address`, { address }),
  rotateCredential: (connectionId: string, credential: string) =>
    put<ControlledConnection>(`/connections/${connectionId}/credential`, { credential }),

  listDelegations: (connectionId?: string) =>
    request(
      `${BASE}/delegations${connectionId ? `?connection_id=${encodeURIComponent(connectionId)}` : ''}`,
    ).then((r) => readJson<{ items: Delegation[] }>(r)),
  grantDelegation: (payload: {
    connection_id: string
    dataset_code: string
    grantee: string
  }) => post<Delegation>('/delegations', payload),
  reconfirmDelegation: (delegationId: string) =>
    post<Delegation>(`/delegations/${delegationId}/reconfirm`),
  revokeDelegation: (delegationId: string) =>
    post<Delegation>(`/delegations/${delegationId}/revoke`),

  consume: (connection_id: string, dataset_code: string) =>
    post<ConnectionHandle>('/connections/consume', { connection_id, dataset_code }),

  listHandovers: (connectionId?: string) =>
    request(
      `${BASE}/handovers${connectionId ? `?connection_id=${encodeURIComponent(connectionId)}` : ''}`,
    ).then((r) => readJson<{ items: Handover[] }>(r)),
  beginHandover: (connection_id: string, to_owner: string) =>
    post<Handover>('/handovers', { connection_id, to_owner }),
  acceptHandover: (handoverId: string) =>
    post<Handover>(`/handovers/${handoverId}/accept`),
  cancelHandover: (handoverId: string) =>
    post<Handover>(`/handovers/${handoverId}/cancel`),

  audit: () => request(`${BASE}/audit`).then((r) => readJson<{ items: AuditEvent[] }>(r)),
}
