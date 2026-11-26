import { NextResponse } from "next/server";
import { activateHma } from "@/lib/hmaProxy/service";

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));
    const status = await activateHma(body?.activationCode);
    return NextResponse.json({ success: true, status });
  } catch (error) {
    const msg = error?.message || "Failed to activate HMA license";
    const isClientError = /required|must contain|invalid/i.test(msg);
    return NextResponse.json({ error: msg }, { status: isClientError ? 400 : 500 });
  }
}
