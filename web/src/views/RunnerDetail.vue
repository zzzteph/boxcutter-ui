<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import { fmtDuration, timeAgo } from '../util'

const route = useRoute()
const id = route.params.id
const r = ref(null)
let timer = null

async function load() { try { r.value = await api.get('/runners/' + id) } catch (e) { /* transient */ } }
function meterClass(v) { return v >= 85 ? 'hi' : (v >= 60 ? 'mid' : '') }
onMounted(async () => { await load(); timer = setInterval(load, 2000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div v-if="r">
    <div class="row" style="justify-content:space-between">
      <h1>{{ r.name || ('runner #' + r.id) }}
        <span class="state" :class="r.status === 'disconnected' ? 'st-stopped' : 'st-done'">{{ r.status }}</span>
      </h1>
      <router-link to="/scanners" class="btn">← Scanners</router-link>
    </div>
    <div class="muted">{{ r.busy_slots }}/{{ r.slots }} slots busy · v{{ r.version || '?' }}
      <span v-if="r.ip"> · <code>{{ r.ip }}</code></span>
      <span v-if="r.host && r.host !== r.ip"> · {{ r.host }}</span> · last beat {{ timeAgo(r.last_heartbeat) }}</div>

    <div class="grid" style="margin-top:16px;grid-template-columns:repeat(auto-fill,minmax(220px,1fr))">
      <div class="card">
        <div class="row" style="justify-content:space-between"><span class="muted">CPU</span>
          <b>{{ r.metrics && r.metrics.cpu != null ? r.metrics.cpu + '%' : 'n/a' }}</b></div>
        <div class="meter" style="margin-top:8px"><div :class="meterClass((r.metrics || {}).cpu || 0)"
          :style="{ width: ((r.metrics || {}).cpu || 0) + '%' }"></div></div>
      </div>
      <div class="card">
        <div class="row" style="justify-content:space-between"><span class="muted">Memory</span>
          <b>{{ r.metrics && r.metrics.mem != null ? r.metrics.mem + '%' : 'n/a' }}</b></div>
        <div class="meter" style="margin-top:8px"><div :class="meterClass((r.metrics || {}).mem || 0)"
          :style="{ width: ((r.metrics || {}).mem || 0) + '%' }"></div></div>
      </div>
    </div>

    <h2 style="margin-top:18px">Running now <span class="muted" style="font-weight:400">({{ (r.current || []).length }})</span></h2>
    <div class="card tablecard">
    <table class="reflow">
      <thead><tr><th>Target</th><th>Template</th><th>Scan</th><th>Started</th></tr></thead>
      <tbody>
        <tr v-for="j in r.current" :key="j.id">
          <td data-label="Target">{{ j.target }}</td>
          <td data-label="Template">{{ j.template }}</td>
          <td data-label="Scan"><router-link :to="'/scans/' + j.scan_id">#{{ j.scan_id }}</router-link></td>
          <td data-label="Started">{{ timeAgo(j.claimed_at) }}</td>
        </tr>
        <tr v-if="!(r.current || []).length"><td colspan="4" class="muted">Idle — no jobs running.</td></tr>
      </tbody>
    </table>
    </div>

    <h2 style="margin-top:18px">Recent jobs</h2>
    <div class="card tablecard">
    <table class="reflow">
      <thead><tr><th>Target</th><th>Template</th><th>Status</th><th>Duration</th><th>Finished</th></tr></thead>
      <tbody>
        <tr v-for="j in r.last_jobs" :key="j.id">
          <td data-label="Target">{{ j.target }}</td>
          <td data-label="Template">{{ j.template }}</td>
          <td data-label="Status"><span class="state" :class="j.status === 'failed' ? 'st-stopped' : 'st-done'">{{ j.status }}</span></td>
          <td data-label="Duration">{{ j.duration_sec != null ? fmtDuration(j.duration_sec) : '—' }}</td>
          <td data-label="Finished">{{ timeAgo(j.finished_at) }}</td>
        </tr>
        <tr v-if="!(r.last_jobs || []).length"><td colspan="5" class="muted">No finished jobs yet.</td></tr>
      </tbody>
    </table>
    </div>
  </div>
</template>
