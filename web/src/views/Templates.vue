<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { api, isAdmin } from '../api'
import Select from '../components/Select.vue'

const KIND_LABEL = { tool: 'Tool', workflow: 'Workflow', ai_agent: 'AI agent' }
// Known boxcutter workflows/tools/agents, with a one-line description, so the picker is self-explanatory.
const CATALOG = {
  workflow: [
    { name: 'web-full', desc: 'Full web-application assessment' },
    { name: 'recon', desc: 'Reconnaissance / asset discovery' },
  ],
  tool: [
    { name: 'httpx', desc: 'HTTP probing & tech detection' },
    { name: 'nuclei', desc: 'Template-based vulnerability scan' },
    { name: 'sqlmap', desc: 'SQL-injection testing' },
    { name: 'fuzz', desc: 'Content / parameter fuzzing' },
  ],
  ai_agent: [
    { name: 'irvin', desc: 'Web pentest agent' },
    { name: 'bob', desc: 'Recon & mapping agent' },
    { name: 'travis', desc: 'API testing agent' },
    { name: 'caleb', desc: 'Exploitation agent' },
  ],
}
const CUSTOM = '__custom__'

const templates = ref([])
const profiles = ref([])
const err = ref('')
const loading = ref(true)
const form = reactive({ name: '', kind: 'tool', specName: 'httpx', customName: '', params: [], context: '', llm_profile_id: null })

function addParam() { form.params.push({ flag: '', value: '' }) }
function rmParam(i) { form.params.splice(i, 1) }

const profileName = (id) => (profiles.value.find(p => p.id === id) || {}).name || ('#' + id)
const options = computed(() => CATALOG[form.kind] || [])
const kindOpts = Object.entries(KIND_LABEL).map(([value, label]) => ({ value, label }))
const specOpts = computed(() => [...options.value.map(o => ({ value: o.name, label: `${o.name} — ${o.desc}` })),
  { value: CUSTOM, label: 'Custom…' }])
const profileOpts = computed(() => profiles.value.map(p => ({ value: p.id, label: `${p.name} (${p.provider})` })))
const resolvedSpec = computed(() => (form.specName === CUSTOM ? form.customName.trim() : form.specName))
const selectedDesc = computed(() => (options.value.find(o => o.name === form.specName) || {}).desc || '')
const canCreate = computed(() => form.name.trim() && resolvedSpec.value &&
  (form.kind !== 'ai_agent' || form.llm_profile_id))

// render a template's params to a preview string (both structured params and legacy flat flags)
function specTokens(spec) {
  const out = []
  for (const p of (spec?.params || [])) { if (!p.flag) continue; out.push(p.flag); if (p.value !== '' && p.value != null) out.push(String(p.value)) }
  for (const f of (spec?.flags || [])) out.push(String(f))
  return out
}
const preview = computed(() => ['boxcutter', resolvedSpec.value,
  ...specTokens({ params: form.params })].filter(Boolean).join(' '))

// when the kind changes, default the picker to that kind's first known item, and suggest a name
watch(() => form.kind, (k) => { form.specName = (CATALOG[k][0] || {}).name || CUSTOM })
watch(resolvedSpec, (s) => { if (s && !form.name.trim()) form.name = s })

async function load() {
  try {
    templates.value = await api.get('/templates')
    profiles.value = await api.get('/llm-profiles')
  } catch (e) { err.value = e.message } finally { loading.value = false }
}
async function create() {
  err.value = ''
  try {
    const params = form.params.filter(p => p.flag.trim())
      .map(p => ({ flag: p.flag.trim().startsWith('-') ? p.flag.trim() : '--' + p.flag.trim(), value: p.value }))
    const body = {
      name: form.name.trim(), kind: form.kind,
      spec: { name: resolvedSpec.value, params, flags: [] },
    }
    if (form.kind === 'ai_agent') { body.context = form.context || null; body.llm_profile_id = form.llm_profile_id }
    await api.post('/templates', body)
    form.name = ''; form.customName = ''; form.params = []; form.context = ''; form.llm_profile_id = null
    form.specName = (CATALOG[form.kind][0] || {}).name || CUSTOM
    await load()
  } catch (e) { err.value = e.message }
}
async function del(id) {
  if (!confirm('Delete this template?')) return
  try { await api.del('/templates/' + id); await load() } catch (e) { alert(e.message) }
}
onMounted(load)
</script>

<template>
  <h1>Templates</h1>
  <div class="card" style="margin-bottom:18px">
    <h2>New template</h2>
    <div class="row" style="gap:14px;align-items:flex-start">
      <div style="flex:1;min-width:140px">
        <label>Kind</label>
        <Select v-model="form.kind" :options="kindOpts" />
      </div>
      <div style="flex:2;min-width:220px">
        <label>{{ KIND_LABEL[form.kind] }}</label>
        <Select v-model="form.specName" :options="specOpts" />
        <input v-if="form.specName === CUSTOM" v-model="form.customName" placeholder="custom name" style="margin-top:6px" />
        <div v-else-if="selectedDesc" class="muted" style="font-size:12px;margin-top:4px">{{ selectedDesc }}</div>
      </div>
      <div style="flex:2;min-width:180px">
        <label>Name</label>
        <input v-model="form.name" :placeholder="resolvedSpec || 'My web scan'" />
      </div>
    </div>

    <label style="margin-top:14px">Boxcutter parameters
      <span class="muted">— flags passed to <code>{{ resolvedSpec || 'boxcutter' }}</code> for every scan using this template</span></label>
    <div v-for="(p, i) in form.params" :key="i" class="kvrow">
      <input v-model="p.flag" placeholder="--severity" />
      <input v-model="p.value" placeholder="high  (leave blank for a boolean flag)" />
      <button class="danger ghost icon" title="Remove" @click="rmParam(i)">✕</button>
    </div>
    <button class="tonal sm" @click="addParam">+ Add parameter</button>
    <pre class="cmd" style="margin-top:10px">{{ preview }}</pre>

    <template v-if="form.kind === 'ai_agent'">
      <label>Default context (guidance for the agent — scans can override per run)</label>
      <textarea v-model="form.context" rows="2" placeholder="Focus on auth and access control"></textarea>
      <label>LLM profile</label>
      <Select v-model="form.llm_profile_id" :options="profileOpts" placeholder="Select a profile…" />
      <p v-if="!profiles.length" class="muted">
        No LLM profiles yet.
        <span v-if="isAdmin()">Create one under <router-link to="/llm-profiles">LLM Profiles</router-link>.</span>
        <span v-else>Ask an admin to create one.</span>
      </p>
    </template>
    <p v-if="err" style="color:var(--bad)">{{ err }}</p>
    <button class="primary" style="margin-top:12px" :disabled="!canCreate" @click="create">Create template</button>
  </div>

  <div class="grid">
    <div v-for="t in templates" :key="t.id" class="card">
      <div class="row" style="justify-content:space-between;align-items:flex-start">
        <b>{{ t.name }}</b><span class="tag" :class="'kind-' + t.kind">{{ KIND_LABEL[t.kind] || t.kind }}</span>
      </div>
      <div class="muted" style="margin-top:8px"><code>{{ t.spec.name }}</code></div>
      <pre v-if="specTokens(t.spec).length" class="cmd sm">{{ specTokens(t.spec).join(' ') }}</pre>
      <div v-if="t.kind === 'ai_agent'" class="muted" style="font-size:12px;margin-top:4px">
        profile: {{ profileName(t.llm_profile_id) }}<span v-if="t.context"> · “{{ t.context }}”</span>
      </div>
      <div class="row" style="margin-top:10px;gap:8px">
        <button class="danger ghost" @click="del(t.id)">Delete</button>
      </div>
    </div>
    <div v-if="loading" class="muted">Loading…</div>
    <div v-else-if="!templates.length" class="muted">No templates yet. Create one above.</div>
  </div>
</template>
