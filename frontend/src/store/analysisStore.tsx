import React, { createContext, useContext, useReducer } from 'react'
import type { AnalysisResult, Session } from '../types/api'

// ============================================================
// STATE
// ============================================================

interface AnalysisState {
  result: AnalysisResult | null
  selectedSession: Session | null
  loading: boolean
  error: string | null
}

const initialState: AnalysisState = {
  result: null,
  selectedSession: null,
  loading: false,
  error: null,
}

// ============================================================
// ACTIONS
// ============================================================

type Action =
  | { type: 'ANALYZE_START' }
  | { type: 'ANALYZE_SUCCESS'; payload: AnalysisResult }
  | { type: 'ANALYZE_ERROR'; payload: string }
  | { type: 'SELECT_SESSION'; payload: Session | null }
  | { type: 'CLEAR' }

function reducer(state: AnalysisState, action: Action): AnalysisState {
  switch (action.type) {
    case 'ANALYZE_START':
      return { ...state, loading: true, error: null }
    case 'ANALYZE_SUCCESS':
      return { ...state, loading: false, result: action.payload, error: null }
    case 'ANALYZE_ERROR':
      return { ...state, loading: false, error: action.payload }
    case 'SELECT_SESSION':
      return { ...state, selectedSession: action.payload }
    case 'CLEAR':
      return initialState
    default:
      return state
  }
}

// ============================================================
// CONTEXT
// ============================================================

interface AnalysisContextValue {
  state: AnalysisState
  dispatch: React.Dispatch<Action>
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null)

export function AnalysisProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState)
  return (
    <AnalysisContext.Provider value={{ state, dispatch }}>
      {children}
    </AnalysisContext.Provider>
  )
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext)
  if (!ctx) throw new Error('useAnalysis must be used within AnalysisProvider')
  return ctx
}
