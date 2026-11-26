import { NextResponse } from "next/server";
import { startHmaTunnel } from "@/lib/hmaProxy/service";

export async function POST(request) {
  try {
    const body = await request.json().catch(() => ({}));
    const result = await startHmaTunnel({
      country: body?.country,
      city: body?.city,
      socks5Port: body?.socks5Port,
      httpPort: body?.httpPort,
      bind: body?.bind,
      protocol: body?.protocol,
      tunnelId: body?.tunnelId,
      autoRegisterPool: body?.autoRegisterPool,
      poolName: body?.poolName,
    });
    return NextResponse.json(result, { status: 201 });
  } catch (error) {
    const msg = error?.message || "Failed to start HMA tunnel";
    const isClientError = /required|invalid|must be|cannot be the same|not activated/i.test(msg);
    return NextResponse.json({ error: msg }, { status: isClientError ? 400 : 500 });
  }
}
