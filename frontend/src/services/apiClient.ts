import {
  AnalyzeURLRequest,
  AnalyzeURLResponse,
  HistoryDetailResponse,
  HistoryListResponse,
  ModelStatusResponse,
  RiskCategory,
} from '../types/api';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export class ApiClientError extends Error {
  public readonly status: number;
  public readonly errorCode: string;

  constructor(status: number, errorCode: string, message: string) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
    this.errorCode = errorCode;
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorCode = `HTTP_${response.status}`;
    let message = 'An unexpected error occurred while communicating with the analysis service.';

    try {
      const data = await response.json();
      if (data && typeof data === 'object') {
        errorCode = data.error_code || errorCode;
        message = data.message || message;
      }
    } catch {
      if (response.status === 429) {
        errorCode = 'RATE_LIMIT_EXCEEDED';
        message = 'Too many requests. Please wait a moment before trying again.';
      } else if (response.status >= 500) {
        errorCode = 'BACKEND_UNAVAILABLE';
        message = 'The URL analysis backend service is currently unavailable.';
      }
    }

    throw new ApiClientError(response.status, errorCode, message);
  }

  return (await response.json()) as T;
}

export async function analyzeUrl(payload: AnalyzeURLRequest): Promise<AnalyzeURLResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new ApiClientError(
      0,
      'NETWORK_ERROR',
      'Unable to reach the backend analysis server. Verify that the FastAPI backend is running.'
    );
  }
  return handleResponse<AnalyzeURLResponse>(response);
}

export async function fetchModelStatus(): Promise<ModelStatusResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/model/status`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new ApiClientError(
      0,
      'NETWORK_ERROR',
      'Unable to reach the backend service to retrieve model status.'
    );
  }
  return handleResponse<ModelStatusResponse>(response);
}

export async function fetchHistory(params?: {
  search?: string;
  riskCategory?: RiskCategory | '';
  limit?: number;
}): Promise<HistoryListResponse> {
  const query = new URLSearchParams();
  if (params?.search && params.search.trim()) {
    query.set('search', params.search.trim());
  }
  if (params?.riskCategory) {
    query.set('risk_category', params.riskCategory);
  }
  if (params?.limit) {
    query.set('limit', String(params.limit));
  }

  const queryString = query.toString();
  const url = `${API_BASE}/history${queryString ? `?${queryString}` : ''}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new ApiClientError(0, 'NETWORK_ERROR', 'Unable to reach the backend service to load history.');
  }
  return handleResponse<HistoryListResponse>(response);
}

export async function fetchHistoryDetail(analysisId: string): Promise<HistoryDetailResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/history/${encodeURIComponent(analysisId)}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new ApiClientError(0, 'NETWORK_ERROR', 'Unable to reach the backend service.');
  }
  return handleResponse<HistoryDetailResponse>(response);
}

export async function deleteHistory(analysisId?: string): Promise<{ deleted_count: number; message: string }> {
  const query = analysisId ? `?analysis_id=${encodeURIComponent(analysisId)}` : '';
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/history${query}`, {
      method: 'DELETE',
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new ApiClientError(0, 'NETWORK_ERROR', 'Unable to reach the backend service.');
  }
  return handleResponse<{ deleted_count: number; message: string }>(response);
}
