<template>
  <section class="page" data-module="security">
    <header class="page-head">
      <div>
        <h2>受控连接安全边界</h2>
        <p class="page-desc">
          连接凭据只在服务端边界内使用：列表与详情仅展示脱敏地址与掩码凭据；
          负责人可按数据集委派使用权，被委派人只能消费连接、无法读取原始凭据。
        </p>
      </div>
    </header>

    <nav class="tab-bar">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        class="tab"
        :class="{ active: activeTab === tab.key }"
        type="button"
        @click="switchTab(tab.key)"
      >
        {{ tab.label }}
      </button>
    </nav>

    <ConnectionsTab v-if="activeTab === 'connections'" />
    <DelegationsTab v-else-if="activeTab === 'delegations'" />
    <HandoversTab v-else-if="activeTab === 'handovers'" />
    <AuditTab v-else />
  </section>
</template>

<script setup lang="ts">
import { ref } from 'vue'

import AuditTab from './AuditTab.vue'
import ConnectionsTab from './ConnectionsTab.vue'
import DelegationsTab from './DelegationsTab.vue'
import HandoversTab from './HandoversTab.vue'

type TabKey = 'connections' | 'delegations' | 'handovers' | 'audit'

const tabs: { key: TabKey; label: string }[] = [
  { key: 'connections', label: '受控连接' },
  { key: 'delegations', label: '使用权委派' },
  { key: 'handovers', label: '负责人移交' },
  { key: 'audit', label: '审计记录' },
]

const activeTab = ref<TabKey>('connections')

function switchTab(key: TabKey) {
  activeTab.value = key
}
</script>

<style scoped>
.tab-bar {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.tab {
  border: none;
  background: none;
  padding: 8px 14px;
  cursor: pointer;
  font-size: 13px;
  color: var(--muted);
  border-bottom: 2px solid transparent;
}
.tab.active {
  color: var(--brand);
  border-bottom-color: var(--brand);
  font-weight: 600;
}
</style>
