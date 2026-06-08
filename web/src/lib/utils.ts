import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: Date | string): string {
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "text-critical";
    case "high":
      return "text-high";
    case "medium":
      return "text-medium";
    case "low":
      return "text-low";
    default:
      return "text-info";
  }
}

export function severityBg(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-critical-bg border-critical/20";
    case "high":
      return "bg-high-bg border-high/20";
    case "medium":
      return "bg-medium-bg border-medium/20";
    case "low":
      return "bg-low-bg border-low/20";
    default:
      return "bg-info-bg border-info/20";
  }
}

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function apiFetch<T = unknown>(
  path: string,
  options?: RequestInit
): Promise<{ success: boolean; data?: T; error?: string }> {
  try {
    const response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });
    return await response.json();
  } catch (error) {
    return { success: false, error: "Network error" };
  }
}