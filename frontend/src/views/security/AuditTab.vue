<template>
  <div>
    <div class="toolbar">
      <button class="btn" type="button" @click="reload">刷新</button>
      <span class="hint">审计事件只记录操作与非敏感标识，凭据与地址认证段不会写入。</span>
    </div>
    <table class="data-table">
      <thead>
        <tr>
          <th>时间 (UTC)</th>
          <th>操作人</th>
          <th>动作</th>
          <th>连接</th>
          <th>数据集</th>
          <th>说明</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="event in events" :key="event.id">
          <td class="mono">{{ event.at }}</td>
          <td>{{ event.actor }}</td>
          <td>{{ event.action }}</td>
          <td class="mono">{{ event.connection_id ? event.connection_id.slice(0, 8) : '—' }}</td>
          <td>{{ event.dataset_code ?? '—' }}</td>
          <td>{{ event.detail }}</td>
        </tr>
        <tr v-if="!events.length">
          <td colspan="6" class="empty-state">暂无审计记录</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { ApiError } from '@/api/client'
import { securityApi, type AuditEvent } from '@/api/security'

const events = ref<AuditEvent[]>([])
const errorMessage = ref('')

async function reload() {
  errorMessage.value = ''
  try {
    events.value = (await securityApi.audit()).items
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '审计记录读取失败'
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
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}
.hint {
  font-size: 12px;
  color: var(--muted);
}
</style>
