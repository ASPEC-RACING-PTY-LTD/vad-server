import { lazy } from 'react'
import { ShieldAlert } from 'lucide-react'
import type { AdminTab } from '../../pages/admin/tabs/registry'

/** Administration > Upload security: uploads that did not pass inspection. */
export default {
  id: 'security',
  label: 'Upload security',
  icon: ShieldAlert,
  order: 27,
  component: lazy(() => import('./SecurityTab')),
  inSidebar: true,
} satisfies AdminTab
