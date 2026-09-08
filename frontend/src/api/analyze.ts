import type { AnalysisResult } from '../types/api'

const API_BASE = '/analyze'

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch(API_BASE, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    let detail = `Server error: ${response.status}`
    try {
      const err = await response.json()
      if (err.detail) detail = err.detail
    } catch {
      // ignore parse failure
    }
    throw new Error(detail)
  }

  return response.json() as Promise<AnalysisResult>
}
