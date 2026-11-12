<template>
  <section class="login-page">
    <form class="login-card" @submit.prevent="submit">
      <h2>受控连接工作台 · 登录</h2>
      <p class="page-desc">
        应用内最小身份验证：口令经 PBKDF2 校验后签发 HMAC 签名令牌，
        凭据不写入日志，会话仅保存在当前浏览器。
      </p>
      <label class="form-item">
        <span>用户名</span>
        <input v-model="username" autocomplete="username" placeholder="alice / bob / carol / dave" />
      </label>
      <label class="form-item">
        <span>口令</span>
        <input v-model="password" type="password" autocomplete="current-password" />
      </label>
      <button class="btn primary" type="submit" :disabled="loading">
        {{ loading ? '验证中…' : '登录' }}
      </button>
      <p v-if="errorMessage" class="error-text">{{ errorMessage }}</p>
      <details class="demo-hint">
        <summary>演示账号</summary>
        <ul>
          <li>alice / alice-pass-2026（连接负责人）</li>
          <li>bob / bob-pass-2026（数据集负责人，被委派人）</li>
          <li>carol / carol-pass-2026（普通浏览者）</li>
          <li>dave / dave-pass-2026（另一连接负责人）</li>
        </ul>
      </details>
      <RouterLink class="back-link" to="/">返回概览</RouterLink>
    </form>
  </section>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import { securityApi } from '@/api/security'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const router = useRouter()
const route = useRoute()

const username = ref('')
const password = ref('')
const loading = ref(false)
const errorMessage = ref('')

async function submit() {
  errorMessage.value = ''
  if (!username.value || !password.value) {
    errorMessage.value = '请输入用户名与口令'
    return
  }
  loading.value = true
  try {
    const result = await securityApi.login(username.value.trim(), password.value)
    session.setSession(result.token, result.user)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError ? error.message : '登录失败，请稍后重试'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  justify-content: center;
  padding-top: 48px;
}
.login-card {
  width: 420px;
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.form-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 13px;
  color: var(--muted);
}
.form-item input {
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 14px;
}
.demo-hint {
  font-size: 12px;
  color: var(--muted);
}
.demo-hint ul {
  margin: 6px 0 0;
  padding-left: 18px;
}
.back-link {
  font-size: 12px;
  color: var(--brand);
}
</style>
