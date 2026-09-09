import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Upload,
  FileText,
  Network,
  ShieldCheck,
} from 'lucide-react'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/analyze', label: 'Analyze PCAP', icon: Upload, exact: false },
  { to: '/report', label: 'Security Report', icon: FileText, exact: false },
  { to: '/sessions', label: 'Sessions', icon: Network, exact: false },
]

export function Sidebar() {
  const location = useLocation()

  return (
    <aside className="sidebar" aria-label="Main navigation">
      {/* Logo */}
      <div className="sidebar-header">
        <div className="sidebar-logo" aria-hidden="true">
          <ShieldCheck />
        </div>
        <span className="sidebar-wordmark">SecureMailScope</span>
      </div>

      {/* Nav */}
      <nav className="sidebar-nav" aria-label="Primary">
        <span className="sidebar-section-label">Navigation</span>
        {navItems.map(({ to, label, icon: Icon, exact }) => {
          return (
            <NavLink
              key={to}
              to={to}
              className={({ isActive: routerActive }) =>
                `nav-item${routerActive && (exact ? location.pathname === to : true) ? ' active' : ''}`
              }
              end={exact}
              aria-label={label}
              title={label}
            >
              <Icon aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <span className="sidebar-footer-text" style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
          v1.0 · PCAP Analysis
        </span>
      </div>
    </aside>
  )
}
