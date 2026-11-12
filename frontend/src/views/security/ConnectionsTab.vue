<template>
  <div>
    <div class="toolbar">
      <button class="btn primary" type="button" @click="showCreate = true">登记受控连接</button>
      <button class="btn" type="button" @click="reload">刷新</button>
      <span v-if="message" class="info-text">{{ message }}</span>
      <span v-if="errorMessage" class="error-text">{{ errorMessage }}</span>
    </div>

    <table class="data-table">
      <thead>
        <tr>
          <th>连接名称</th>
          <th>类型</th>
          <th>接入地址（按角色脱敏）</th>
          <th>凭据</th>
          <th>负责人</th>
          <th>凭据版本</th>
          <th>地址版本</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="conn in connections" :key="conn.id">
          <td>{{ conn.name }}<span v-if="conn.is_owner" class="badge owner">我的</span></td>
          <td>{{ conn.connection_type }}</td>
          <td class="mono">{{ conn.address }}</td>
          <td class="mono">{{ conn.credential }}</td>
          <td>{{ conn.owner }}</td>
          <td>v{{ conn.credential_version }}</td>
          <td>v{{ conn.address_version }}</td>
          <td class="row-actions">
            <button class="link" type="button" @click="openAddress(conn)">改地址</button>
            <button class="link" type="button" @click="openCredential(conn)">轮换凭据</button>
          </td>
        </tr>
        <tr v-if="!connections.length">
          <td colspan="8" class="empty-state">暂无受控连接</td>
        </tr>
      </tbody>
    </table>

    <!-- 登记 -->
    <div v-if="showCreate" class="modal-mask" @click.self="showCreate = false">
      <form class="modal" @submit.prevent="create">
        <h3>登记受控连接</h3>
        <label class="form-item"><span>连接名称</span><input v-model="form.name" required /></label>
        <label class="form-item"><span>连接类型</span><input v-model="form.connection_type" required /></label>
        <label class="form-item">
          <span>接入地址</span>
          <input v-model="form.address" required placeholder="mysql://user:pass@host:3306/db" />
        </label>
        <label class="form-item">
          <span>认证凭据</span>
          <input v-model="form.credential" type="password" required autocomplete="new-password" />
        </label>
        <p class="hint">原始凭据仅存储于服务端内存，提交后任何界面都不再回显。</p>
        <div class="modal-actions">
          <button class="btn" type="button" @click="showCreate = false">取消</button>
          <button class="btn primary" type="submit">登记</button>
        </div>
      </form>
    </div>

    <!-- 改地址 -->
    <div v-if="addressTarget" class="modal-mask" @click.self="addressTarget = null">
      <form class="modal" @submit.prevent="submitAddress">
        <h3>变更接入地址 · {{ addressTarget.name }}</h3>
        <p class="hint">
          仅当主机（host）变化时，该连接上的既有委派会全部挂起，需在「使用权委派」页重新确认；
          仅路径 / 端口变化不影响授权。
        </p>
        <label class="form-item">
          <span>新接入地址</span>
          <input v-model="newAddress" required />
        </label>
        <div class="modal-actions">
          <button class="btn" type="button" @click="addressTarget = null">取消</button>
          <button class="btn primary" type="submit">提交变更</button>
        </div>
      </form>
    </div>

    <!-- 轮换凭据 -->
    <div v-if="credentialTarget" class="modal-mask" @click.self="credentialTarget = null">
      <form class="modal" @submit.prevent="submitCredential">
        <h3>轮换认证凭据 · {{ credentialTarget.name }}</h3>
        <p class="hint">轮换不影响仍然有效的授权，也不会让其他数据集继承访问权。</p>
        <label class="form-item">
          <span>新认证凭据</span>
          <input v-model="newCredential" type="password" required autocomplete="new-password" />
        </label>
        <div class="modal-actions">
          <button class="btn" type="button" @click="credentialTarget = null">取消</button>
          <button class="btn primary" type="submit">轮换</button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { ApiError } from '@/api/client'
import { securityApi, type ControlledConnection } from '@/api/security'

const connections = ref<ControlledConnection[]>([])
const errorMessage = ref('')
const message = ref('')
const showCreate = ref(false)
const form = ref({ name: '', connection_type: '', address: '', credential: '' })

const addressTarget = ref<ControlledConnection | null>(null)
const newAddress = ref('')
const credentialTarget = ref<ControlledConnection | null>(null)
const newCredential = ref('')

function flash(text: string) {
  message.value = text
  window.setTimeout(() => (message.value = ''), 4000)
}

async function reload() {
  errorMessage.value = ''
  try {
    connections.value = (await securityApi.listConnections()).items
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '连接列表读取失败'
  }
}

async function create() {
  errorMessage.value = ''
  try {
    await securityApi.createConnection({ ...form.value })
    showCreate.value = false
    form.value = { name: '', connection_type: '', address: '', credential: '' }
    flash('受控连接已登记')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '登记失败'
  }
}

function openAddress(conn: ControlledConnection) {
  addressTarget.value = conn
  newAddress.value = ''
}

async function submitAddress() {
  if (!addressTarget.value) return
  try {
    await securityApi.updateAddress(addressTarget.value.id, newAddress.value)
    addressTarget.value = null
    flash('接入地址已更新')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '地址变更失败'
  }
}

function openCredential(conn: ControlledConnection) {
  credentialTarget.value = conn
  newCredential.value = ''
}

async function submitCredential() {
  if (!credentialTarget.value) return
  try {
    await securityApi.rotateCredential(credentialTarget.value.id, newCredential.value)
    credentialTarget.value = null
    flash('凭据已轮换，授权保持不变')
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '凭据轮换失败'
  }
}

onMounted(reload)
defineExpose({ reload })
</script>

<style scoped>
.toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 10px;
}
.badge {
  display: inline-block;
  margin-left: 6px;
  padding: 1px 6px;
  border-radius: 10px;
  font-size: 11px;
}
.badge.owner {
  background: #e8f0fe;
  color: var(--brand);
}
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
.form-item input {
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
.info-text {
  color: #067647;
  font-size: 12px;
}
</style>
