const HEADERS = ["x-opencode-client", "x-opencode-session", "x-opencode-session-id", "x-session-id", "user-agent"]
const LIMIT = 1024 * 1024

/** Inspect a clone only; never return body text, tool arguments, or header values. */
export async function captureRequestTools(request: Request) {
  const headers = Object.fromEntries(HEADERS.map((name) => [name, request.headers.has(name)]))
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  try {
    reader = request.clone().body?.getReader()
  } catch {
    return { headers, status: "capture-unavailable" }
  }
  if (!reader) return { headers, status: "no-body" }
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("Capture deadline")), 1000)
  })
  let size = 0
  const chunks: Uint8Array[] = []
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), deadline])
      if (done) break
      size += value.byteLength
      if (size > LIMIT) return { headers, status: "body-too-large" }
      chunks.push(value)
    }
    const bytes = new Uint8Array(size)
    let offset = 0
    for (const chunk of chunks) {
      bytes.set(chunk, offset)
      offset += chunk.byteLength
    }
    const body = JSON.parse(new TextDecoder().decode(bytes))
    if (!body || typeof body !== "object" || Array.isArray(body))
      return { headers, status: "unsupported-body" }
    const tools = body.tools ?? []
    if (!Array.isArray(tools)) return { headers, status: "unsupported-tools" }
    const names: string[] = []
    for (const tool of tools) {
      const name = tool?.function?.name ?? tool?.name
      if (typeof name !== "string" || !/^[a-zA-Z0-9_.:-]{1,100}$/.test(name))
        return { headers, status: "unsupported-tools" }
      names.push(name)
    }
    return { headers, status: "captured", tools: names }
  } catch {
    return { headers, status: "capture-unavailable" }
  } finally {
    clearTimeout(timer)
    // Do not await cancellation of a tee: it can wait for the original request consumer.
    void reader.cancel().catch(() => {})
  }
}
