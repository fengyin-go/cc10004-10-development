<template>
  <div>
    <div class="toolbar">
      <button class="btn primary" type="button" @click="showGrant = true">授予使用权</button>
      <button class="btn" type="button" @click="reload">刷新</button>
      <span v-if="message" class="info-text">{{ message }}</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </div>

    <table class="data-table">
      <thead>
        <tr>
          <th>连接</th>
          <th>数据集编号</th>
          <th>授权负责人</th>
          <th>被委派人</th>
          <th>状态</th>
          <th>挂起地址版本</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in delegations" :key="item.id">
          <td class="mono">{{ connectionName(item.connection_id) }}</td>
          <td>{{ item.dataset_code }}</td>
          <td>{{ item.granter }}</td>
          <td>{{ item.grantee }}</td>
          <td>
            <span class="badge" :class="statusClass(item.status)">{{ item.status }}</span>
          </td>
          <td>{{ item.suspended_address_version ?? '—' }}</td>
          <td class="row-actions">
            <button class="link" type="button" @click="reconfirm(item)" :disabled="item.status !== '待重新确认'">
              重新确认
            </button>
            <button class="link danger" type="button" @click="revoke(item)" :disabled="item.status === '已撤回'">
              撤回
            </button>
            <button class="link" type="button" @click="tryConsume(item)">测试消费</button>
          </td>
        </tr>
        <tr v-if="!delegations.length">
          <td colspan="7" class="empty-state">暂无委派记录</td>
        </tr>
      </tbody>
    </table>

    <p class="hint">
      「测试消费」走委派唯一凭据通道：成功时只返回连接句柄（credential_handle），
      不返回原始凭据；无有效授权或处于待重新确认状态时会被服务端拒绝。
    </p>

    <div v-if="consumeResult" class="modal-mask" @click.self="consumeResult = null">
      <div class="modal">
        <h3>连接消费结果</h3>
        <pre class="result-box">{{ JSON.stringify(consumeResult, null, 2) }}</pre>
        <div class="modal-actions">
          <button class="btn primary" type="button" @click="consumeResult = null">知道了</button>
        </div>
      </div>
    </div>

    <div v-if="showGrant" class="modal-mask" @click.self="showGrant = false">
      <form class="modal" @submit.prevent="grant">
        <h3>授予连接使用权</h3>
        <label class="form-item">
          <span>受控连接</span>
          <select v-model="form.connection_id" required>
            <option value="" disabled>请选择你负责的连接</option>
            <option v-for="conn in ownConnections" :key="conn.id" :value="conn.id">
              {{ conn.name }}（{{ conn.id.slice(0, 8) }}）
            </option>
          </select>
        </label>
        <label class="form-item">
          <span>数据集编号</span>
          <input v-model="form.dataset_code" required placeholder="如 DATA-1001" />
        </label>
        <label class="form-item">
          <span>被委派人</span>
          <input v-model="form.grantee" required placeholder="用户名，如 bob" />
        </label>
        <p class="hint">授权仅限该数据集上的连接消费，被委派人无法读取原始凭据，也不会继承到其他数据集。</p>
        <div class="modal-actions">
          <button class="btn" type="button" @click="showGrant = false">取消</button>
          <button class="btn primary" type="submit">授予</button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { ApiError } from '@/api/client'
import {
  securityApi,
  type ConnectionHandle,
  type ControlledConnection,
  type Delegation,
} from '@/api/security'

const delegations = ref<Delegation[]>([])
const connections = ref<ControlledConnection[]>([])
const errorMessage = ref('')
const message = ref('')
const showGrant = ref(false)
const consumeResult = ref<ConnectionHandle | null>(null)
const form = ref({ connection_id: '', dataset_code: '', grantee: '' })

const ownConnections = computed(() => connections.value.filter((item) => item.is_owner))

function connectionName(id: string): string {
  const conn = connections.value.find((item) => item.id === id)
  return conn ? `${conn.name} · ${id.slice(0, 8)}` : id.slice(0, 8)
}

function statusClass(status: string): string {
  if (status === '有效') return 'ok'
  if (status === '待重新确认') return 'warn'
  return 'muted'
}

function flash(text: string) {
  message.value = text
  window.setTimeout(() => (message.value = ''), 4000)
}

async function reload() {
  errorMessage.value = ''
  try {
    const [delegationData, connectionData] = await Promise.all([
      securityApi.listDelegations(),
      securityApi.listConnections(),
    ])
    delegations.value = delegationData.items
    connections.value = connectionData.items
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '委派列表读取失败'
  }
}

async function grant() {
  errorMessage.value = ''
  try {
    await securityApi.grantDelegation({ ...form.value })
    showGrant.value = false
    form.value = { connection_id: '', dataset_code: '', grantee: '' }
    flash('委派已授予')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '授予失败'
  }
}

async function reconfirm(item: Delegation) {
  errorMessage.value = ''
  try {
    await securityApi.reconfirmDelegation(item.id)
    flash('委派已重新确认并恢复有效')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '重新确认失败'
  }
}

async function revoke(item: Delegation) {
  errorMessage.value = ''
  try {
    await securityApi.revokeDelegation(item.id)
    flash('委派已撤回')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '撤回失败'
  }
}

async function tryConsume(item: Delegation) {
  errorMessage.value = ''
  try {
    consumeResult.value = await securityApi.consume(
      item.connection_id,
      item.dataset_code,
    )
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError
        ? `消费被拒绝（${error.status}）：${error.message}`
        : '消费失败'
  }
}

onMounted(() => {
  void reload()
})
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 10px;
}
.badge {
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
}
.badge.ok {
  background: #e7f6ec;
  color: #067647;
}
.badge.warn {
  background: #fef3c7;
  color: #b54708;
}
.badge.muted {
  background: #f1f5f9;
  color: var(--muted);
}
.link.danger {
  color: #b42318;
}
.link:disabled {
  color: #cbd5e1;
  cursor: not-allowed;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}
.hint {
  font-size: 12px;
  color: var(--muted);
}
.modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 20;
}
.modal {
  width: 520px;
  background: #fff;
  border-radius: 10px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.form-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
  color: var(--muted);
}
.form-item input,
.form-item select {
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
}
.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
.result-box {
  background: #0f172a;
  color: #d1fae5;
  padding: 12px;
  border-radius: 8px;
  font-size: 12px;
  max-height: 280px;
  overflow: auto;
}
.info-text {
  color: #067647;
  font-size: 12px;
}
</style>
