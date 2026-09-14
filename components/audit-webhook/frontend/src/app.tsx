import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { ConfigProvider, message } from "antd";
import zhCN from "antd/locale/zh_CN";
import "dayjs/locale/zh-cn";
import { apiFetch, errMessage } from "./api";
import "./styles.css";

/** Mount a page component with the shared antd theme and Chinese locale. */
export function mountPage(Page: React.ComponentType) {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <ConfigProvider
        locale={zhCN}
        theme={{ token: { colorPrimary: "#2563eb", borderRadius: 6 } }}
      >
        <Page />
      </ConfigProvider>
    </StrictMode>
  );
}

/** Whitelisted user ids ([whitelist] users in audit.toml), fetched once
 * per page view. Pages show these users as VIP用户, everyone else as
 * 普通用户. */
export function useWhitelist(): string[] {
  const [whitelist, setWhitelist] = useState<string[]>([]);

  useEffect(() => {
    apiFetch<{ users: string[] }>("/api/whitelist")
      .then((data) => setWhitelist(data.users))
      .catch((err) => message.error(`加载白名单失败：${errMessage(err)}`));
  }, []);

  return whitelist;
}
