<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api'
import { timeAgo } from '../util'
import Select from '../components/Select.vue'

const route = useRoute()
const router = useRouter()
const LIMIT = 50
const SEVS = ['Critical', 'High', 'Medium', 'Low', 'Info']
const sevOpts = [{ value: '', label: 'All severities' }, ...SEVS.map(s => ({ value: s, label: s }))]
const items = ref([]); const total = ref(0); const offset = ref(0)
const q = ref(route.query.q || '')
const severity = ref(route.query.severity || '')
const state = ref(''); const sort = ref('severity'); const dir = ref('desc')
let timer = null

function url() {
  let u = `/findings?limit=${LIMIT}&offset=${offset.value}&state=${state.value}&sort=${sort.value}&dir=${dir.value}`
  if (severity.value) u += `&severity=${severity.value}`
  if (q.value) u += `&q=${encodeURIComponent(q.value)}`
  return u
}
async function load() { try { const r = await api.get(url()); items.value = r.items; total.value = r.total } catch (e) { /* transient */ } }
function apply() { offset.value = 0; load() }
function page(d) { offset.value = Math.max(0, offset.value + d * LIMIT); load() }
function setSort(col) {
  if (sort.value === col) dir.value = dir.value === 'asc' ? 'desc' : 'asc'
  else { sort.value = col; dir.value = col === 'last_seen' ? 'desc' : 'asc' }
  apply()
}
function sortInd(col) { return sort.value === col ? (dir.value === 'asc' ? ' ▲' : ' ▼') : '' }
onMounted(async () => { await load(); timer = setInterval(load, 4000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="row" style="justify-content:space-between;align-items:center;gap:10px">
    <h1 style="margin:0">Findings <span class="muted" style="font-weight:400;font-size:16px">({{ total }})</span></h1>
    <div class="row" style="gap:8px">
      <Select v-model="severity" :options="sevOpts" auto @change="apply" />
      <input v-model="q" placeholder="search all findings…" style="width:auto;max-width:240px" @keyup.enter="apply" @input="apply" />
    </div>
  </div>
  <div class="muted" style="font-size:12px;margin:6px 0">Across all scans. Click a column to sort · click a finding to open its scan.</div>
  <div class="card tablecard">
  <table class="reflow findings rows">
    <thead><tr>
      <th class="sortable" @click="setSort('severity')">Sev{{ sortInd('severity') }}</th>
      <th class="sortable" @click="setSort('title')">Title{{ sortInd('title') }}</th>
      <th class="sortable" @click="setSort('target')">Asset{{ sortInd('target') }}</th>
      <th>Scan</th>
      <th class="sortable" @click="setSort('state')">State{{ sortInd('state') }}</th>
      <th>Seen</th>
    </tr></thead>
    <tbody>
      <tr v-for="f in items" :key="f.id" :class="'sevrow-' + f.severity" style="cursor:pointer" @click="router.push('/scans/' + f.scan_id)">
        <td data-label="Sev"><span class="badge" :class="'sev-' + f.severity">{{ f.severity }}</span></td>
        <td data-label="Title">{{ f.title }}</td>
        <td data-label="Asset">{{ f.target }}</td>
        <td data-label="Scan">{{ f.scan }}</td>
        <td data-label="State"><span class="state" :class="'state-' + f.state">{{ f.state }}</span></td>
        <td data-label="Seen" style="white-space:nowrap">{{ timeAgo(f.last_seen) }}</td>
      </tr>
      <tr v-if="!items.length"><td colspan="6" class="muted">No findings match.</td></tr>
    </tbody>
  </table>
  </div>
  <div v-if="total > LIMIT" class="row pager">
    <button class="ghost" :disabled="offset === 0" @click="page(-1)">← Prev</button>
    <span class="muted">{{ offset + 1 }}–{{ Math.min(offset + LIMIT, total) }} of {{ total }}</span>
    <button class="ghost" :disabled="offset + LIMIT >= total" @click="page(1)">Next →</button>
  </div>
</template>
