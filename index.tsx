/*
 * AttachmentVirusScanner - Custom Vencord Plugin
 * Right-click any file attachment → "Scan for Viruses" (VirusTotal)
 * Authors: StarFire & MW-Lord
 */

import { addContextMenuPatch, removeContextMenuPatch, NavContextMenuPatchCallback } from "@api/ContextMenu";
import definePluginSettings from "@api/Settings";
import definePlugin, { OptionType } from "@utils/types";
import { Menu } from "@webpack/common";
import { openModal } from "@utils/modal";
import { showToast } from "@utils/toasts";
import { Logger } from "@utils/Logger";

const logger = new Logger("AttachmentVirusScanner");

const settings = definePluginSettings({
    virusTotalApiKey: {
        type: OptionType.STRING,
        description: "VirusTotal API Key (pre-filled)",
        default: "e863d3371a3d1542e5e151213a5bcc06a930e15f48bc1d47f823043ac5a291a3",
        placeholder: "Your key is set"
    }
});

function ScanResultModal({ stats, hash, filename }: { stats: any; hash: string; filename: string }) {
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = (stats.harmless || 0) + (stats.undetected || 0) + malicious + suspicious;

    const verdict = malicious > 0 || suspicious > 2
        ? { color: "#ed4245", text: "⚠️ POTENTIALLY MALICIOUS", sub: `${malicious} engines flagged it` }
        : { color: "#3ba55c", text: "✅ CLEAN / SAFE", sub: "No detections" };

    return (
        <div style={{ padding: "20px", color: "white", background: "#36393f", borderRadius: "8px" }}>
            <h2 style={{ margin: "0 0 16px 0" }}>VirusTotal Scan — {filename}</h2>
            <div style={{ fontSize: "24px", fontWeight: "bold", color: verdict.color, marginBottom: "8px" }}>
                {verdict.text}
                </div>
          <div style={{ marginBottom: "16px" }}>{verdict.sub}</div>

            <div style={{ background: "#2f3136", padding: "12px", borderRadius: "6px", marginBottom: "16px" }}>
                <div>Malicious: <b>{malicious}</b></div>
                <div>Suspicious: <b>{suspicious}</b></div>
                <div>Harmless: <b>{stats.harmless || 0}</b></div>
                <div>Undetected: <b>{stats.undetected || 0}</b></div>
                <div style={{ marginTop: "8px" }}>Total engines: <b>{total}</b></div>
            </div>

            <a
                href={`https://www.virustotal.com/gui/file/${hash}/detection`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "#00b0f4", textDecoration: "underline" }}
            >
                Full report on VirusTotal →
            </a>
        </div>
    );
}

async function scanAttachment(attachment: any) {
    const apiKey = settings.store.virusTotalApiKey?.trim();
    if (!apiKey) {
        showToast({ message: "VirusTotal API key missing – check settings", type: 2 });
        return;
    }

    const url = attachment.url || attachment.proxy_url;
    if (!url) {
        showToast({ message: "Cannot access file URL", type: 2 });
        return;
    }

    try {
        showToast({ message: "Scanning with VirusTotal...", type: 1 });

        const res = await fetch(url, { cache: "no-store" });
        if (!res.ok) throw new Error(`Download failed: ${res.status}`);

        const blob = await res.blob();
        const buffer = await blob.arrayBuffer();

        const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
        const hashHex = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");

        const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${hashHex}`, {
            headers: { "x-apikey": apiKey }
        });

        if (vtRes.status === 404) {
            showToast({ message: "File unknown to VirusTotal (new file – treat with caution)", type: 1 });
            return;
        }

        if (!vtRes.ok) {
            const err = await vtRes.json().catch(() => ({}));
            throw new Error(err?.error?.message || `VT API error (${vtRes.status})`);
        }

        const data = await vtRes.json();
        const stats = data.data?.attributes?.last_analysis_stats ?? {};

        openModal(modalProps => (
            <ScanResultModal stats={stats} hash={hashHex} filename={attachment.filename || "File"} {...modalProps} />
        ));

    } catch (err: any) {
        logger.error("Scan failed:", err);
        showToast({ message: `Scan error: ${err.message || "Unknown issue"}`, type: 2 });
    }
}

const patch: NavContextMenuPatchCallback = (data, menu) => {
    let attachment = null;

    // Common paths in 2026 Vencord/Discord menus
    if (data.attachment) {
        attachment = data.attachment;
    } else if (data.target?.props?.attachment) {
        attachment = data.target.props.attachment;
    } else if (data.message?.attachments?.length > 0) {
        // Take first attachment if multiple (common case)
        attachment = data.message.attachments[0];
    } else if (data.target?.props?.message?.attachments?.length > 0) {
        attachment = data.target.props.message.attachments[0];
    }

    if (!attachment || (!attachment.url && !attachment.proxy_url)) {
        logger.debug("No valid attachment found in context data");
        return;
    }

    logger.debug("Found attachment:", attachment.filename || "unnamed");

    // Ensure children is array
    let children = menu.props.children;
    if (!Array.isArray(children)) {
        children = children ? [children] : [];
    }

    children.push(
        <Menu.MenuGroup key="virus-scan-group">
            <Menu.MenuItem
                id="scan-for-viruses"
                label="Scan for Viruses"
                icon={() => <span style={{ fontSize: "1.2em" }}>🛡️</span>}
                action={() => scanAttachment(attachment)}
            />
        </Menu.MenuGroup>
    );

    menu.props.children = children;
};

export default definePlugin({
    name: "AttachmentVirusScanner",
    description: "Right-click attachments → Scan for Viruses (VirusTotal)",
    authors: [
        { name: "StarFire", id: 1297220734875340840n },
        { name: "MW-Lord", id: 1328096083628523523n }
    ],

    settings,

    start() {
        // Patch the most common menu for attachments (in messages)
        addContextMenuPatch("message", patch);
        // Fallback for direct attachment menus if separate
        addContextMenuPatch("attachment", patch);
        logger.log("Plugin started – right-click attachments to scan");
    },

    stop() {
        removeContextMenuPatch("message", patch);
        removeContextMenuPatch("attachment", patch);
    }
});
