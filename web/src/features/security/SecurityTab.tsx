import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { Badge, Button, EmptyState, ErrorState, PageLoader, useUI } from '../../components/ui'
import { errorMessage, get, put } from '../../lib/api'
import { formatBytes, formatDate } from '../../lib/format'

type Item = {
  user_id: number
  username: string
  sha256: string
  verdict: 'flagged' | 'quarantined' | 'clean'
  kind: string
  detail: string
  engine: string
  scanned_at: number
  name: string
  node_id: number
  size: number
}

/** Uploads that did not pass inspection, from every account (administrators included). */
export default function SecurityTab() {
  const qc = useQueryClient()
  const { toast, confirm } = useUI()
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ['admin-upload-security'], queryFn: () => get<{ items: Item[]; clamav: boolean }>('/admin/security/uploads') })
  if (isLoading) return <PageLoader />
  if (error || !data) return <ErrorState error={error} onRetry={refetch} />

  const review = async (it: Item, verdict: 'clean' | 'flagged' | 'quarantined') => {
    if (verdict === 'clean') {
      const ok = await confirm({
        title: `Release ${it.name || 'this file'}?`,
        message: `${it.detail} (${it.engine}). Only release it if you checked the file and know it is safe; it can then be opened, previewed and shared again.`,
        confirmLabel: 'Release',
      })
      if (!ok) return
    }
    try {
      await put('/admin/security/uploads', { user_id: it.user_id, sha256: it.sha256, verdict })
      qc.invalidateQueries({ queryKey: ['admin-upload-security'] })
    } catch (e) {
      toast('error', 'Not changed', errorMessage(e))
    }
  }

  return (
    <div className="space-y-4">
      <section className="card space-y-2 p-5 text-sm">
        <h2 className="font-semibold">Every upload is untrusted</h2>
        <p className="text-slate-600 dark:text-slate-300">
          Uploads from every account and device, administrators included, are inspected. Programs, scripts, shortcuts, installers and macro documents are <strong>flagged</strong>: they are only ever downloaded as files, never previewed or
          processed, and cannot be shared publicly. Content disguised as something harmless (a program named .mp4){data.clamav ? ' and anything ClamAV detects' : ''} is <strong>quarantined</strong>: it cannot be opened, downloaded, shared or
          copied until you release it. Each account&apos;s files stay in their own space, so a file can never reach another account&apos;s files.
        </p>
        <p className="text-xs text-slate-500">
          Antivirus scanning: {data.clamav ? 'ClamAV is connected.' : 'not configured. Set VAULTDOCK_CLAMD to a ClamAV daemon (for example tcp://clamav:3310) to scan every upload with it too.'}
        </p>
      </section>
      <div className="card overflow-x-auto">
        {data.items.length === 0 ? (
          <EmptyState icon={<ShieldCheck className="size-6" />} title="Nothing flagged" description="Uploads that look like programs, scripts or malware show up here." />
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-slate-200 text-left text-xs text-slate-500 uppercase dark:border-slate-800">
              <tr>
                <th className="px-4 py-2.5">File</th>
                <th className="px-4 py-2.5">Account</th>
                <th className="px-4 py-2.5">Finding</th>
                <th className="hidden px-4 py-2.5 md:table-cell">When</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.items.map((it) => (
                <tr key={it.user_id + it.sha256} className="border-b border-slate-100 last:border-0 dark:border-slate-800">
                  <td className="px-4 py-2.5">
                    <div className="font-medium">{it.name || <span className="text-slate-400">(deleted)</span>}</div>
                    <div className="font-mono text-[11px] text-slate-400">
                      {it.sha256.slice(0, 16)} · {formatBytes(it.size)}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">{it.username}</td>
                  <td className="px-4 py-2.5">
                    <Badge tone={it.verdict === 'quarantined' ? 'red' : 'amber'}>{it.verdict}</Badge> <span className="text-slate-600 dark:text-slate-300">{it.detail}</span>
                    <div className="text-xs text-slate-400">{it.engine}</div>
                  </td>
                  <td className="hidden px-4 py-2.5 text-xs text-slate-500 md:table-cell">{formatDate(it.scanned_at)}</td>
                  <td className="px-4 py-2.5 text-right whitespace-nowrap">
                    {it.verdict === 'quarantined' ? (
                      <Button size="sm" variant="ghost" onClick={() => review(it, 'clean')}>
                        Release
                      </Button>
                    ) : (
                      <Button size="sm" variant="ghost" className="text-rose-600" icon={<ShieldAlert className="size-4" />} onClick={() => review(it, 'quarantined')}>
                        Quarantine
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
