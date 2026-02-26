/*
 * AttachmentVirusScanner - Custom Vencord Plugin
 * Right-click any message (Reply/Pin/Copy menu) → "Scan File" if it has an attachment
 * Authors: StarFire & MW-Lord
 */

import { addContextMenuPatch, removeContextMenuPatch } from "@api/ContextMenu";
import { definePluginSettings } from "@api/Settings";
import definePlugin, { OptionType } from "@utils/types";
import { Menu } from "@webpack/common";
import { openModal } from "@utils/modal";
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

interface AttachmentType {
    url?: string;
    proxy_url?: string;
    filename?: string;
}

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

async function scanAttachment(attachment: AttachmentType | null) {
    if (!attachment || (!attachment.url && !attachment.proxy_url)) return;

    const apiKey = settings.store.virusTotalApiKey?.trim();
    if (!apiKey) {
        console.log("[Scan File] API key missing – check settings");
        return;
    }

    const url = attachment.url || attachment.proxy_url;

    try {
        console.log("[Scan File] Starting scan...");

        const res = await fetch(url, { cache: "no-store" });
        if (!res.ok) throw new Error("Download failed");

        const blob = await res.blob();
        const buffer = await blob.arrayBuffer();

        const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
        const hashHex = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");

        const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${hashHex}`, {
            headers: { "x-apikey": apiKey }
        });

        if (vtRes.status === 404) {
            console.log("[Scan File] File not in VirusTotal yet (new file)");
            return;
        }

        if (!vtRes.ok) throw new Error("VirusTotal error");

        const data = await vtRes.json();
        const stats = data.data?.attributes?.last_analysis_stats ?? {};

        openModal(props => (
            <ScanResultModal stats={stats} hash={hashHex} filename={attachment.filename || "File"} {...props} />
        ));

    } catch (err: any) {
        console.log("[Scan File] Error:", err.message || "Unknown");
    }
}

const patch = (data: any, menu: any) => {
    // Only look in the standard message menu data
    let attachment = data?.message?.attachments?.[0] 
                  || data?.target?.props?.message?.attachments?.[0];

    if (!attachment || (!attachment.url && !attachment.proxy_url)) return;

    console.log("[Scan File] Found file in message menu:", attachment.filename);

    const children = Array.isArray(menu.props.children) 
        ? menu.props.children 
        : menu.props.children ? [menu.props.children] : [];

    children.push(
        <Menu.MenuGroup key="scan-virus">
            <Menu.MenuItem
                id="scan-virus"
                label="Scan File"
                icon={() => <span style={{ fontSize: "1.2em" }}>🛡️</span>}
                action={() => scanAttachment(attachment)}
            />
        </Menu.MenuGroup>
    );

    menu.props.children = children;
};

export default definePlugin({
    name: "AttachmentVirusScanner",
    description: "Right-click messages → Scan File (VirusTotal) in Reply/Pin menu",
    authors: [
        { name: "StarFire", id: 1297220734875340840n },
        { name: "MW-Lord", id: 1328096083628523523n }
    ],

    settings,

    start() {
        addContextMenuPatch("message", patch);
        console.log("[Scan File] Plugin started – message menu ready");
    },

    stop() {
        removeContextMenuPatch("message", patch);
    }
});
