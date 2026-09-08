import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import Dashboard from './pages/Dashboard'
import AnalyzePCAP from './pages/AnalyzePCAP'
import SecurityReport from './pages/SecurityReport'
import Sessions from './pages/Sessions'
import { AnalysisProvider } from './store/analysisStore'

function App() {
  return (
    <AnalysisProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analyze" element={<AnalyzePCAP />} />
            <Route path="/report" element={<SecurityReport />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AnalysisProvider>
  )
}

export default App
