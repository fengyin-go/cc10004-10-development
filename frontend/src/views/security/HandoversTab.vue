<template>
  <div>
    <div class="toolbar">
      <button class="btn primary" type="button" @click="showBegin = true">发起负责人移交</button>
      <button class="btn" type="button" @click="reload">刷新</button>
      <span v-if="message" class="info-text">{{ message }}</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </div>

    <table class="data-table">
      <thead>
        <tr>
          <th>连接</th>
          <th>原负责人</th>
          <th>新负责人</th>
          <th>状态</th>
          <th>发起时间</th>
          <th>处理时间</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in handovers" :key="item.id">
          <td class="mono">{{ connectionName(item.connection_id) }}</td>
          <td>{{ item.from_owner }}</td>
          <td>{{ item.to_owner }}</td>
          <td><span class="badge" :class="statusClass(item.status)">{{ item.status }}</span></td>
          <td>{{ item.created_at }}</td>
          <td>{{ item.decided_at ?? '—' }}</td>
          <td class="row-actions">
            <button
              class="link"
              type="button"
              :disabled="item.status !== '待接收' || item.to_owner !== session.username"
              @click="accept(item)"
            >
              接收
            </button>
            <button
              class="link danger"
              type="button"
              :disabled="item.status !== '待接收'"
              @click="cancel(item)"
            >
              取消
            </button>
          </td>
        </tr>
        <tr v-if="!handovers.length">
          <td colspan="7" class="empty-state">暂无移交记录</td>
        </tr>
      </tbody>
    </table>

    <p class="hint">
      接收完成后责任关系立即转移并留痕：原负责人无法再改动连接或委派；
      既有委派跟随连接保留，可由新负责人继续管理。
    </p>

    <div v-if="showBegin" class="modal-mask" @click.self="showBegin = false">
      <form class="modal" @submit.prevent="begin">
        <h3>发起负责人移交</h3>
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
          <span>新负责人用户名</span>
          <input v-model="form.to_owner" required placeholder="如 dave" />
        </label>
        <div class="modal-actions">
          <button class="btn" type="button" @click="showBegin = false">取消</button>
          <button class="btn primary" type="submit">发起移交</button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { ApiError } from '@/api/client'
import { securityApi, type ControlledConnection, type Handover } from '@/api/security'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const handovers = ref<Handover[]>([])
const connections = ref<ControlledConnection[]>([])
const errorMessage = ref('')
const message = ref('')
const showBegin = ref(false)
const form = ref({ connection_id: '', to_owner: '' })

const ownConnections = computed(() => connections.value.filter((item) => item.is_owner))

function connectionName(id: string): string {
  const conn = connections.value.find((item) => item.id === id)
  return conn ? `${conn.name} · ${id.slice(0, 8)}` : id.slice(0, 8)
}

function statusClass(status: string): string {
  if (status === '已移交') return 'ok'
  if (status === '待接收') return 'warn'
  return 'muted'
}

function flash(text: string) {
  message.value = text
  window.setTimeout(() => (message.value = ''), 4000)
}

async function reload() {
  errorMessage.value = ''
  try {
    const [handoverData, connectionData] = await Promise.all([
      securityApi.listHandovers(),
      securityApi.listConnections(),
    ])
    handovers.value = handoverData.items
    connections.value = connectionData.items
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '移交记录读取失败'
  }
}

async function begin() {
  errorMessage.value = ''
  try {
    await securityApi.beginHandover(form.value.connection_id, form.value.to_owner)
    showBegin.value = false
    form.value = { connection_id: '', to_owner: '' }
    flash('移交已发起，等待新负责人接收')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '发起移交失败'
  }
}

async function accept(item: Handover) {
  errorMessage.value = ''
  try {
    await securityApi.acceptHandover(item.id)
    flash('已接收负责人身份，责任关系已移交')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '接收失败'
  }
}

async function cancel(item: Handover) {
  errorMessage.value = ''
  try {
    await securityApi.cancelHandover(item.id)
    flash('移交已取消')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '取消失败'
  }
}

onMounted(reload)
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
  width: 460px;
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
.info-text {
  color: #067647;
  font-size: 12px;
}
</style>
