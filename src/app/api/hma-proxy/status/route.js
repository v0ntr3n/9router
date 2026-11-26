import { NextResponse } from "next/server";
import { getHmaStatus } from "@/lib/hmaProxy/service";

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const checkIp = searchParams.get("checkIp") === "true";
    const status = await getHmaStatus({ checkIp });
    return NextResponse.json(status);
  } catch (error) {
    console.log("Error reading HMA proxy status:", error);
    return NextResponse.json(
      { error: error?.message || "Failed to fetch HMA proxy status" },
      { status: 500 }
    );
  }
}
