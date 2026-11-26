import { NextResponse } from "next/server";
import { stopHmaTunnel } from "@/lib/hmaProxy/service";

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));
    const result = await stopHmaTunnel(body?.tunnelId || "default");
    return NextResponse.json(result);
  } catch (error) {
    const msg = error?.message || "Failed to stop HMA tunnel";
    const isClientError = /invalid|must be/i.test(msg);
    return NextResponse.json({ error: msg }, { status: isClientError ? 400 : 500 });
  }
}
