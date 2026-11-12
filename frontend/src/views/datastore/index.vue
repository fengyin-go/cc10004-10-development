<template>
  <section class="page" data-module="datastore">
    <header class="page-head">
      <div>
        <h2>数据集管理</h2>
        <p class="page-desc">
          数据集登记跨模块接入受控连接：必须选择一个你拥有负责人身份或有效委派的受控连接，
          越权提交会被服务端拒绝；数据集记录只保存连接编号引用，不复制任何凭据。
        </p>
      </div>
      <div class="page-actions">
        <button class="btn primary" type="button" @click="openCreate">登记数据集定义</button>
        <button class="btn" type="button" @click="exportRows">导出数据集管理清单</button>
      </div>
    </header>

    <div class="stat-row">
      <article v-for="item in stats" :key="item.label" class="stat-card">
        <span class="stat-label">{{ item.label }}</span>
        <strong class="stat-value">{{ item.value }}</strong>
      </article>
    </div>

    <form class="filter-bar" @submit.prevent="reload">
      <label v-for="field in filterFields" :key="field" class="filter-item">
        <span>{{ field }}</span>
        <input v-model="filters[field]" :placeholder="`按${field}检索`" />
      </label>
      <button class="btn" type="submit">查询</button>
      <button class="btn ghost" type="button" @click="resetFilters">重置条件</button>
    </form>

    <table class="data-table">
      <thead>
        <tr>
          <th v-for="column in columns" :key="column">{{ column }}</th>
          <th>受控连接编号</th>
          <th>登记人</th>
          <th>可执行动作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)">
          <td v-for="column in columns" :key="column">{{ row[column] ?? '—' }}</td>
          <td class="mono">{{ shortId(row['受控连接编号']) }}</td>
          <td>{{ row['登记人'] ?? '—' }}</td>
          <td class="row-actions">
            <button
              v-for="action in actions"
              :key="action"
              class="link"
              type="button"
              @click="runAction(action, row)"
            >
              {{ action }}
            </button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="columns.length + 3" class="empty-state">暂无数据集管理数据，可先登记数据集定义</td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot">
      <span>共 {{ total }} 条数据集管理记录</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </footer>

    <div v-if="showCreate" class="modal-mask" @click.self="closeCreate">
      <form class="modal" @submit.prevent="submitCreate">
        <h3>登记数据集定义</h3>
        <p v-if="!session.isAuthenticated" class="warn-text">
          当前未登录，登记需要可验证身份，请先
          <RouterLink to="/login">登录</RouterLink>。
        </p>
        <label class="form-item">
          <span>数据集编号</span>
          <input v-model="form['数据集编号']" required placeholder="如 DATA-1001" />
        </label>
        <label class="form-item">
          <span>数据集名称</span>
          <input v-model="form['数据集名称']" required />
        </label>
        <label class="form-item">
          <span>来源表名</span>
          <input v-model="form['来源表名']" required />
        </label>
        <label class="form-item">
          <span>受控连接（按授权过滤）</span>
          <select v-model="form['受控连接编号']" required>
            <option value="" disabled>请选择受控连接</option>
            <option v-for="conn in availableConnections" :key="conn.id" :value="conn.id">
              {{ conn.name }} · {{ conn.owner }} · 地址 {{ conn.address }}
            </option>
          </select>
        </label>
        <p class="hint">
          可选项同时包含你负责的连接与被委派的连接；若在某数据集上没有有效授权（含主机变更后待重新确认的委派），
          提交时服务端会返回 403。
        </p>
        <p v-if="submitMessage" :class="submitOk ? 'ok-text' : 'error-text'">{{ submitMessage }}</p>
        <div class="modal-actions">
          <button class="btn" type="button" @click="closeCreate">取消</button>
          <button class="btn primary" type="submit" :disabled="!session.isAuthenticated || submitting">
            {{ submitting ? '提交中…' : '提交登记' }}
          </button>
        </div>
      </form>
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { ApiError, request, readJson } from '@/api/client'
import { securityApi, type ControlledConnection } from '@/api/security'
import { useSessionStore } from '@/stores/session'

type Row = Record<string, string | number | null>

const session = useSessionStore()
const ENDPOINT = '/api/datastore'
const columns = ['数据集编号', '数据集名称', '来源表名', '字段列表', '更新策略', '数据采样比例', '生命周期天数', '缓存开关']
const actions = ['提交审核', '生效发布', '废弃下线']
const stats = [{ label: '数据集定义总数', value: 0 }, { label: '已生效数据集', value: 0 }, { label: '待审核数据集', value: 0 }]

const rows = ref<Row[]>([])
const total = ref(0)
const errorMessage = ref('')
const filters = ref<Record<string, string>>({})
const filterFields = columns.slice(0, 3)

const showCreate = ref(false)
const submitting = ref(false)
const submitMessage = ref('')
const submitOk = ref(false)
const availableConnections = ref<ControlledConnection[]>([])
const form = ref<Record<string, string>>({
  数据集编号: '',
  数据集名称: '',
  来源表名: '',
  受控连接编号: '',
})

function shortId(value: unknown): string {
  return typeof value === 'string' && value ? `${value.slice(0, 8)}…` : '—'
}

function resetFilters() {
  filters.value = {}
  void reload()
}

function exportRows() {
  window.open(`${ENDPOINT}/export`, '_blank')
}

async function openCreate() {
  submitMessage.value = ''
  form.value = { 数据集编号: '', 数据集名称: '', 来源表名: '', 受控连接编号: '' }
  showCreate.value = true
  if (session.isAuthenticated) {
    try {
      // 全部连接都可作为候选；最终是否有权由服务端按「连接 + 数据集」判定，
      // 前端不做授权决策，避免与服务端边界不一致。
      availableConnections.value = (await securityApi.listConnections()).items
    } catch (error) {
      submitOk.value = false
      submitMessage.value = error instanceof ApiError ? error.message : '受控连接列表读取失败'
      availableConnections.value = []
    }
  } else {
    availableConnections.value = []
  }
}

function closeCreate() {
  showCreate.value = false
}

async function submitCreate() {
  submitMessage.value = ''
  submitting.value = true
  try {
    const response = await request(ENDPOINT, {
      method: 'POST',
      body: JSON.stringify({ values: { ...form.value } }),
    })
    const payload = await readJson<{ ok: boolean; message: string }>(response)
    submitOk.value = payload.ok
    submitMessage.value = payload.ok ? '数据集定义已登记' : payload.message
    if (payload.ok) {
      showCreate.value = false
      await reload()
    }
  } catch (error) {
    submitOk.value = false
    if (error instanceof ApiError && error.status === 403) {
      submitMessage.value = `越权提交已被拒绝：${error.message}`
    } else if (error instanceof ApiError && error.status === 401) {
      submitMessage.value = '登录已失效，请重新登录后再登记'
    } else {
      submitMessage.value = error instanceof Error ? error.message : '登记失败'
    }
  } finally {
    submitting.value = false
  }
}

async function runAction(action: string, row: Row) {
  errorMessage.value = ''
  try {
    const response = await request(`${ENDPOINT}/${row.id}/actions`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    })
    if (!response.ok) {
      throw new Error('数据集管理动作未生效，请稍后重试')
    }
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '数据集管理操作失败'
  }
}

async function reload() {
  errorMessage.value = ''
  const query = new URLSearchParams(filters.value as Record<string, string>).toString()
  try {
    const response = await request(`${ENDPOINT}?${query}`)
    if (!response.ok) {
      throw new Error('数据集定义列表读取失败')
    }
    const payload = await response.json()
    rows.value = payload.items ?? []
    total.value = payload.total ?? rows.value.length
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '数据集管理列表读取失败'
  }
}

onMounted(reload)
</script>

<style scoped>
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
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
.hint {
  font-size: 12px;
  color: var(--muted);
  margin: 0;
}
.warn-text {
  font-size: 12px;
  color: #b54708;
}
.ok-text {
  color: #067647;
  font-size: 12px;
}
</style>
