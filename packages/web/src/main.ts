import "./style.css";
import { cleanFile, type CleanResult } from "@file-cleaner/core";

const dropzone = document.getElementById("dropzone") as HTMLDivElement;
const fileInput = document.getElementById("fileInput") as HTMLInputElement;
const pickBtn = document.getElementById("pick") as HTMLButtonElement;
const results = document.getElementById("results") as HTMLElement;

const BADGE: Record<
  CleanResult["reason"],
  { cls: string; label: string }
> = {
  cleaned: { cls: "badge--cleaned", label: "Cleaned" },
  "no-junk": { cls: "badge--none", label: "Already clean" },
  "false-positive": { cls: "badge--warn", label: "Skipped (suspicious)" },
  "unknown-type": { cls: "badge--error", label: "Unsupported" },
  "too-small": { cls: "badge--error", label: "Too small" },
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function toText(bytes: Uint8Array): string {
  // Decode the removed bytes as UTF-8 text; non-printable bytes become "·".
  const decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return Array.from(decoded, (ch) => {
    const code = ch.codePointAt(0)!;
    return code < 0x20 || code === 0x7f ? "·" : ch;
  }).join("");
}

function cleanedName(name: string): string {
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return `${name}-cleaned`;
  return `${name.slice(0, dot)}-cleaned${name.slice(dot)}`;
}

function download(bytes: Uint8Array, name: string) {
  // Copy into a fresh ArrayBuffer so the Blob part type is unambiguous.
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  const blob = new Blob([ab], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function createPendingCard(file: File): HTMLDivElement {
  const card = document.createElement("div");
  card.className = "card";

  const row = document.createElement("div");
  row.className = "card__row";

  const spinner = document.createElement("span");
  spinner.className = "spinner";

  const main = document.createElement("div");
  main.className = "card__main";

  const name = document.createElement("div");
  name.className = "card__name";
  name.textContent = file.name;

  const meta = document.createElement("div");
  meta.className = "card__meta";
  meta.textContent = `${formatBytes(file.size)} · processing…`;

  main.append(name, meta);
  row.append(spinner, main);
  card.append(row);

  results.prepend(card);
  results.hidden = false;
  return card;
}

function renderCard(card: HTMLDivElement, file: File, result: CleanResult) {
  card.replaceChildren();
  const badge = BADGE[result.reason];

  const row = document.createElement("div");
  row.className = "card__row";

  const main = document.createElement("div");
  main.className = "card__main";

  const name = document.createElement("div");
  name.className = "card__name";
  name.textContent = file.name;

  const meta = document.createElement("div");
  meta.className = "card__meta";
  const parts = [`${result.fileType}`, formatBytes(file.size)];
  if (result.reason === "cleaned") {
    parts.push(`removed ${result.junkBytes} junk byte${result.junkBytes === 1 ? "" : "s"}`);
  } else if (result.reason === "false-positive") {
    parts.push(`${result.junkBytes} trailing bytes — left untouched`);
  }
  meta.textContent = parts.join(" · ");

  main.append(name, meta);

  const badgeEl = document.createElement("span");
  badgeEl.className = `badge ${badge.cls}`;
  badgeEl.textContent = badge.label;

  row.append(main, badgeEl);

  if (result.cleaned) {
    const dl = document.createElement("button");
    dl.className = "btn btn--ghost";
    dl.textContent = "Download";
    dl.addEventListener("click", () => download(result.data, cleanedName(file.name)));
    row.append(dl);
  }

  card.append(row);

  // Show the actual removed bytes (hex + ASCII) so the user can inspect them.
  if (result.junk.length > 0) {
    const dump = document.createElement("div");
    dump.className = "junk";

    const label = document.createElement("div");
    label.className = "junk__label";
    label.textContent = `Removed ${result.junk.length} byte${result.junk.length === 1 ? "" : "s"}:`;

    const text = document.createElement("code");
    text.className = "junk__text";
    text.textContent = toText(result.junk);

    dump.append(label, text);
    card.append(dump);
  }
}

async function processFile(card: HTMLDivElement, file: File) {
  // Yield so the spinner paints before the (possibly heavy) read + parse.
  await new Promise((r) => requestAnimationFrame(() => r(null)));
  const buf = new Uint8Array(await file.arrayBuffer());
  const result = cleanFile(buf);
  renderCard(card, file, result);
}

function handleFiles(files: FileList | File[]) {
  // Create every pending card first (all spinners visible at once),
  // then process all files in parallel.
  const jobs = Array.from(files).map((file) => ({
    file,
    card: createPendingCard(file),
  }));
  for (const { card, file } of jobs) processFile(card, file);
}

// --- wiring ---
pickBtn.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  if (fileInput.files) handleFiles(fileInput.files);
  fileInput.value = "";
});

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});

["dragenter", "dragover"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  }),
);
["dragleave", "drop"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
  }),
);
dropzone.addEventListener("drop", (e) => {
  const dt = (e as DragEvent).dataTransfer;
  if (dt?.files?.length) handleFiles(dt.files);
});
