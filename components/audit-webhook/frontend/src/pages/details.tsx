import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Input,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import { apiFetch, errMessage, fmtTime } from "../api";
import { mountPage } from "../app";

interface RequestRow {
  id: number;
  sandbox_id: string;
  user_id: string | null;
  /** true when the sandbox resource no longer exists (history) */
  sandbox_deleted: boolean;
  uri: string;
  request_time: string;
  received_at: string;
}

const PAGE_SIZE = 50;

function DetailsPage() {
  // Filter is pre-filled from ?sandbox_id= or ?user_id= when navigating
  // from the summary page (a user link passes user_id, a bare sandbox
  // without one passes sandbox_id).
  const query = new URLSearchParams(window.location.search);
  const initialSandbox = query.get("sandbox_id") ?? "";
  const initialUser = query.get("user_id") ?? "";
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [sandboxInput, setSandboxInput] = useState(initialSandbox);
  const [sandboxId, setSandboxId] = useState(initialSandbox);
  const [userId, setUserId] = useState(initialUser);
  const [page, setPage] = useState(1);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String((page - 1) * PAGE_SIZE),
      });
      if (initialUser) params.set("user_id", userId);
      else if (sandboxId) params.set("sandbox_id", sandboxId);
      const data = await apiFetch<{ total: number; items: RequestRow[] }>(
        `/api/requests?${params}`
      );
      setRows(data.items);
      setTotal(data.total);
    } catch (err) {
      message.error(`加载请求详情失败：${errMessage(err)}`);
    } finally {
      setLoading(false);
    }
  }, [page, sandboxId, userId, initialUser]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(load, 10000);
    return () => clearInterval(timer);
  }, [autoRefresh, load]);

  const onTableChange = (pagination: TablePaginationConfig) => {
    if (pagination.current) setPage(pagination.current);
  };

  const columns: ColumnsType<RequestRow> = [
    { title: "ID", dataIndex: "id", key: "id", width: 90 },
    {
      title: "沙箱 ID",
      dataIndex: "sandbox_id",
      key: "sandbox_id",
      render: (id: string, row: RequestRow) => (
        <Space size={4}>
          <Typography.Text copyable={{ text: id }}>{id}</Typography.Text>
          {row.sandbox_deleted && <Tag color="default">已删除</Tag>}
        </Space>
      ),
    },
    {
      title: "用户 ID",
      dataIndex: "user_id",
      key: "user_id",
      width: 180,
      render: (id: string | null) => id ?? "-",
    },
    {
      title: "URI",
      dataIndex: "uri",
      key: "uri",
      render: (uri: string) => (
        <Tooltip title={uri}>
          <span className="uri-cell">{uri}</span>
        </Tooltip>
      ),
    },
    {
      title: "请求时间",
      dataIndex: "request_time",
      key: "request_time",
      width: 180,
      render: (iso: string) => fmtTime(iso),
    },
    {
      title: "接收时间",
      dataIndex: "received_at",
      key: "received_at",
      width: 180,
      render: (iso: string) => fmtTime(iso),
    },
  ];

  return (
    <>
      <header className="app-header">
        <h1>
          OpenSandbox 请求详情
          {initialUser ? `（用户 ${initialUser}）` : ""}
        </h1>
        <Space>
          <label>
            自动刷新（10s）{" "}
            <Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} />
          </label>
          <Button onClick={load}>刷新</Button>
        </Space>
      </header>
      <main className="app-main">
        <div className="table-card">
          <div className="table-toolbar">
            <Typography.Link href="/">← 返回总表</Typography.Link>
            <Input.Search
              placeholder="按沙箱 ID 精确过滤"
              allowClear
              value={sandboxInput}
              onChange={(e) => setSandboxInput(e.target.value)}
              onSearch={(value) => {
                setSandboxId(value.trim());
                setPage(1);
              }}
              style={{ width: 360 }}
            />
            <Button
              onClick={() => {
                setSandboxInput("");
                setSandboxId("");
                setUserId("");
                setPage(1);
              }}
            >
              重置
            </Button>
            <div className="spacer" />
            <Typography.Text type="secondary">共 {total} 条</Typography.Text>
          </div>
          <Table<RequestRow>
            rowKey="id"
            columns={columns}
            dataSource={rows}
            loading={loading}
            onChange={onTableChange}
            size="middle"
            pagination={{
              current: page,
              pageSize: PAGE_SIZE,
              total,
              showSizeChanger: false,
              showQuickJumper: true,
            }}
            locale={{ emptyText: "暂无记录" }}
          />
        </div>
      </main>
    </>
  );
}

mountPage(DetailsPage);
