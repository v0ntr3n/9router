import { NextResponse } from "next/server";
import { listHmaCountries } from "@/lib/hmaProxy/service";

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const forceRefresh = searchParams.get("refresh") === "true";
    const countries = await listHmaCountries({ forceRefresh });
    return NextResponse.json({ countries });
  } catch (error) {
    return NextResponse.json(
      { error: error?.message || "Failed to load HMA countries" },
      { status: 500 }
    );
  }
}
