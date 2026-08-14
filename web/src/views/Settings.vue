<script setup>
import { ref, reactive, onMounted } from 'vue'
import { api, isAdmin, getUser, setUser } from '../api'
import { timeAgo } from '../util'
import Select from '../components/Select.vue'

const roleOpts = ['user', 'admin']

const docsUrl = '/docs'    // same origin/port as the app (Vite proxies it in dev; the API serves it in prod)
const redocUrl = '/redoc'

const me = getUser() || {}
const admin = isAdmin()
const pw = reactive({ current: '', next: '', msg: '', err: '' })
const users = ref([])
const nu = reactive({ username: '', password: '', role: 'user', err: '' })

async function changePw() {
  pw.msg = ''; pw.err = ''
  try {
    await api.changePassword(pw.current, pw.next)
    setUser(await api.me()); pw.current = ''; pw.next = ''; pw.msg = 'Password changed.'
  } catch (e) { pw.err = e.message }
}
async function loadUsers() { if (admin) users.value = await api.get('/users') }
async function createUser() {
  nu.err = ''
  try {
    await api.post('/users', { username: nu.username.trim(), password: nu.password, role: nu.role })
    nu.username = ''; nu.password = ''; nu.role = 'user'; await loadUsers()
  } catch (e) { nu.err = e.message }
}
async function setRole(u, role) { try { await api.patch('/users/' + u.id, { role }); await loadUsers() } catch (e) { alert(e.message) } }
async function resetPw(u) {
  const p = prompt(`New password for ${u.username}:`)
  if (!p) return
  try { await api.patch('/users/' + u.id, { password: p }); alert('Password reset; user must change it on next login.') }
  catch (e) { alert(e.message) }
}
async function del(u) {
  if (!confirm(`Delete user ${u.username}?`)) return
  try { await api.del('/users/' + u.id); await loadUsers() } catch (e) { alert(e.message) }
}

// ---- personal API keys ----
const keys = ref([])
const keyName = ref('')
const newKey = ref(null)      // {name, prefix, key} shown once
async function loadKeys() { try { keys.value = await api.get('/api-keys') } catch (e) { /* ignore */ } }
async function createKey() {
  try { newKey.value = await api.post('/api-keys', { name: keyName.value || 'key' }); keyName.value = ''; await loadKeys() }
  catch (e) { alert(e.message) }
}
async function revokeKey(k) {
  if (!confirm(`Revoke key ${k.prefix}… ?`)) return
  try { await api.del('/api-keys/' + k.id); await loadKeys() } catch (e) { alert(e.message) }
}

// ---- system (API-only) users (admin) ----
const sysName = ref('')
const newSys = ref(null)      // {username, prefix, key} shown once
async function createSys() {
  try { newSys.value = await api.post('/system-users', { username: sysName.value }); sysName.value = ''; await loadUsers() }
  catch (e) { alert(e.message) }
}

onMounted(() => { loadUsers(); loadKeys() })
</script>

<template>
  <h1>Settings</h1>

  <div class="card" style="max-width:460px;margin-bottom:18px">
    <h2>Change password</h2>
    <label>Current password</label>
    <input v-model="pw.current" type="password" autocomplete="current-password" />
    <label>New password</label>
    <input v-model="pw.next" type="password" autocomplete="new-password" @keyup.enter="changePw" />
    <p v-if="pw.err" style="color:var(--bad)">{{ pw.err }}</p>
    <p v-if="pw.msg" style="color:var(--ok)">{{ pw.msg }}</p>
    <button class="primary" style="margin-top:12px" :disabled="!pw.current || !pw.next" @click="changePw">Update</button>
  </div>

  <h2>API</h2>
  <p class="muted">Full REST API with interactive docs:
    <a :href="docsUrl" target="_blank" rel="noopener">Swagger UI</a> ·
    <a :href="redocUrl" target="_blank" rel="noopener">ReDoc</a>.
    Authenticate with a key below (send it as <code>X-API-Key</code> or <code>Authorization: Bearer &lt;key&gt;</code>).</p>

  <h2 style="margin-top:14px">API keys</h2>
  <div class="card" style="margin:10px 0">
    <div class="row" style="gap:12px;align-items:flex-end">
      <div style="flex:1;min-width:200px"><label>New key name</label><input v-model="keyName" placeholder="ci, laptop, …" @keyup.enter="createKey" /></div>
      <button class="primary" @click="createKey">Create key</button>
    </div>
    <div v-if="newKey" class="card" style="margin-top:10px;background:var(--surface-2)">
      <b>Copy your key now — it won't be shown again:</b>
      <div><code style="word-break:break-all">{{ newKey.key }}</code></div>
    </div>
  </div>
  <div class="card tablecard">
  <table class="reflow">
    <thead><tr><th>Name</th><th>Prefix</th><th>Last used</th><th></th></tr></thead>
    <tbody>
      <tr v-for="k in keys" :key="k.id">
        <td data-label="Name"><b>{{ k.name }}</b></td>
        <td data-label="Prefix"><code>{{ k.prefix }}…</code></td>
        <td data-label="Last used"><span class="muted">{{ k.last_used_at ? timeAgo(k.last_used_at) : 'never' }}</span></td>
        <td data-label=""><button class="danger ghost" @click="revokeKey(k)">Revoke</button></td>
      </tr>
      <tr v-if="!keys.length"><td colspan="4" class="muted">No API keys yet.</td></tr>
    </tbody>
  </table>
  </div>

  <template v-if="admin">
    <h2>Users</h2>
    <div class="card" style="margin:10px 0">
      <div class="row" style="gap:12px;align-items:flex-end">
        <div style="flex:1;min-width:160px"><label>Username</label><input v-model="nu.username" /></div>
        <div style="flex:1;min-width:160px"><label>Password</label><input v-model="nu.password" type="password" autocomplete="new-password" /></div>
        <div style="min-width:120px"><label>Role</label>
          <Select v-model="nu.role" :options="roleOpts" />
        </div>
        <button class="primary" :disabled="!nu.username || !nu.password" @click="createUser">Add user</button>
      </div>
      <p v-if="nu.err" style="color:var(--bad);margin-top:8px">{{ nu.err }}</p>
    </div>

    <div class="card tablecard">
    <table class="reflow">
      <thead><tr><th>User</th><th>Role</th><th>Status</th><th></th></tr></thead>
      <tbody>
        <tr v-for="u in users" :key="u.id">
          <td data-label="User"><b>{{ u.username }}</b><span v-if="u.id === me.id" class="muted"> (you)</span></td>
          <td data-label="Role">{{ u.role }}</td>
          <td data-label="Status"><span class="muted">{{ u.must_change_password ? 'must change pw' : 'active' }}</span></td>
          <td data-label="">
            <div class="row" style="gap:6px">
              <button v-if="u.role !== 'admin'" @click="setRole(u, 'admin')">Make admin</button>
              <button v-else-if="u.id !== me.id" @click="setRole(u, 'user')">Make user</button>
              <button @click="resetPw(u)">Reset pw</button>
              <button v-if="u.id !== me.id" class="danger ghost" @click="del(u)">Delete</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    </div>

    <h2 style="margin-top:18px">System users (API only)</h2>
    <p class="muted">A system user has no password and can't log in to the UI — it authenticates only with its
      API key. Use it for CI, scripts, or integrations.</p>
    <div class="card" style="margin:10px 0">
      <div class="row" style="gap:12px;align-items:flex-end">
        <div style="flex:1;min-width:200px"><label>System username</label><input v-model="sysName" placeholder="ci-bot" @keyup.enter="createSys" /></div>
        <button class="primary" :disabled="!sysName" @click="createSys">Create system user</button>
      </div>
      <div v-if="newSys" class="card" style="margin-top:10px;background:var(--surface-2)">
        <b>System user “{{ newSys.username }}” created. Copy its key now — shown once:</b>
        <div><code style="word-break:break-all">{{ newSys.key }}</code></div>
      </div>
    </div>
  </template>
</template>
