import { useCallback, useEffect, useRef, useState } from "react";
import {
  Button,
  DatePicker,
  Input,
  Popconfirm,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import type { FilterValue, SorterResult } from "antd/es/table/interface";
import type { Dayjs } from "dayjs";
import { apiFetch, errMessage, fmtTime, logout } from "../api";
import { mountPage } from "../app";

interface SandboxRow {
  /** group key: the user id when known, otherwise the bare sandbox id */
  uid: string;
  /** NULL on per-sandbox groups (sandboxes without a cluster user id) */
  user_id: string | null;
  /** the group's current (non-deleted) sandbox id */
  sandbox_id: string;
  /** node IP of the current sandbox's pod (synced from the cluster) */
  node_ip: string | null;
  /** number of non-deleted sandbox members in this group */
  sandbox_count: number;
  /** false = every member discovered in the cluster, no request yet */
  accessed: boolean;
  /** earliest member BatchSandbox creationTimestamp */
  created_at: string | null;
  /** latest member request time */
  request_time: string | null;
  /** summed member request count */
  request_count: number;
}

const { RangePicker } = DatePicker;
const PAGE_SIZE = 50;
/** Default server-side sort; cancelling a column sort falls back to it. */
const DEFAULT_SORT = "-request_time";
/**
 * Column-click cycle: 降序 → 升序 → 降序 ... The repeated third entry keeps
 * antd's nextSortDirection index in range, so the cycle never reaches its
 * "cancel sort" state. A cancel would force the sort somewhere else (the
 * server always needs a sort key), which reads as the indicator jumping
 * to the 最新请求时间 column - with this cycle the indicator stays on the
 * clicked column.
 */
const SORT_DIRECTIONS = ["descend", "ascend", "descend"] as const;

function SummaryPage() {
  const [rows, setRows] = useState<SandboxRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const [sort, setSort] = useState<string>(DEFAULT_SORT);
  const [page, setPage] = useState(1);
  const [autoRefresh, setAutoRefresh] = useState(false);

  // Guards against out-of-order responses: only the latest load()'s result
  // is applied (rapid sort/search clicks fire overlapping requests).
  const loadSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    setLoading(true);
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String((page - 1) * PAGE_SIZE),
        sort,
      });
      if (search) params.set("search", search);
      // Date pickers cover whole days in the browser's local timezone.
      if (range?.[0]) params.set("time_from", range[0].startOf("day").toISOString());
      if (range?.[1]) params.set("time_to", range[1].endOf("day").toISOString());
      const data = await apiFetch<{ total: number; items: SandboxRow[] }>(
        `/api/sandboxes?${params}`
      );
      if (seq !== loadSeq.current) return; // a newer request took over
      setRows(data.items);
      setTotal(data.total);
    } catch (err) {
      if (seq === loadSeq.current) {
        message.error(`加载沙箱总表失败：${errMessage(err)}`);
      }
    } finally {
      if (seq === loadSeq.current) setLoading(false);
    }
  }, [page, sort, search, range]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(load, 10000);
    return () => clearInterval(timer);
  }, [autoRefresh, load]);

  const applySearch = (value: string) => {
    setSearch(value.trim());
    setPage(1);
  };

  const resetFilters = () => {
    setSearchInput("");
    setSearch("");
    setRange(null);
    setSort(DEFAULT_SORT);
    setPage(1);
  };

  // The sortDirections cycle above never emits a "cancel sort" event, so
  // the sorter always carries a direction. An empty order (antd sends an
  // empty sorter object on a cancel) can only arrive as an edge case -
  // fall back to the default sort there rather than leaving the
  // controlled sortOrder stuck on the last direction.
  const onTableChange = (
    pagination: TablePaginationConfig,
    _filters: Record<string, FilterValue | null>,
    sorter: SorterResult<SandboxRow> | SorterResult<SandboxRow>[]
  ) => {
    const s = Array.isArray(sorter) ? sorter[0] : sorter;
    if (pagination.current) setPage(pagination.current);
    const nextSort = s?.order
      ? s.order === "ascend"
        ? String(s.field)
        : `-${s.field}`
      : DEFAULT_SORT;
    if (nextSort !== sort) {
      setSort(nextSort);
      setPage(1);
    }
  };

  const columns: ColumnsType<SandboxRow> = [
    {
      title: "用户 ID",
      dataIndex: "uid",
      key: "uid",
      render: (id: string) => id,
    },
    {
      title: "当前沙箱 ID",
      dataIndex: "sandbox_id",
      key: "sandbox_id",
      render: (id: string) => <Typography.Text copyable={{ text: id }}>{id}</Typography.Text>,
    },
    {
      title: "状态",
      dataIndex: "accessed",
      key: "accessed",
      width: 90,
      sorter: true,
      sortDirections: [...SORT_DIRECTIONS],
      sortOrder:
        sort === "accessed" ? "ascend" : sort === "-accessed" ? "descend" : null,
      render: (accessed: boolean) =>
        accessed ? (
          <Tag color="green">已访问</Tag>
        ) : (
          <Tag color="orange">未访问</Tag>
        ),
    },
    {
      title: "创建时间",
      dataIndex: "created_at",
      key: "created_at",
      width: 180,
      sorter: true,
      sortDirections: [...SORT_DIRECTIONS],
      sortOrder:
        sort === "created_at" ? "ascend" : sort === "-created_at" ? "descend" : null,
      render: (iso: string | null) => fmtTime(iso),
    },
    {
      title: "节点 IP",
      dataIndex: "node_ip",
      key: "node_ip",
      width: 140,
      render: (ip: string | null) => ip ?? "-",
    },
    {
      title: "最新请求时间",
      dataIndex: "request_time",
      key: "request_time",
      width: 180,
      sorter: true,
      sortDirections: [...SORT_DIRECTIONS],
      sortOrder:
        sort === "request_time" ? "ascend" : sort === "-request_time" ? "descend" : null,
      render: (iso: string | null) => fmtTime(iso),
    },
    {
      title: "累计请求数",
      dataIndex: "request_count",
      key: "request_count",
      width: 120,
      sorter: true,
      sortDirections: [...SORT_DIRECTIONS],
      sortOrder:
        sort === "request_count" ? "ascend" : sort === "-request_count" ? "descend" : null,
      render: (count: number) => <Tag color="geekblue">{count}</Tag>,
    },
    {
      title: "操作",
      key: "action",
      width: 110,
      render: (_: unknown, row: SandboxRow) => (
        <Typography.Link
          onClick={() => {
            window.location.href = `/details?${
              row.user_id
                ? `user_id=${encodeURIComponent(row.user_id)}`
                : `sandbox_id=${encodeURIComponent(row.uid)}`
            }`;
          }}
        >
          访问详情
        </Typography.Link>
      ),
    },
  ];

  return (
    <>
      <header className="app-header">
        <h1>OpenSandbox 用户访问总表</h1>
        <Space>
          <label>
            自动刷新（10s）{" "}
            <Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} />
          </label>
          <Button onClick={load}>刷新</Button>
          <Popconfirm title="确定退出登录？" onConfirm={logout} okText="退出" cancelText="取消">
            <Button danger>退出登录</Button>
          </Popconfirm>
        </Space>
      </header>
      <main className="app-main">
        <div className="table-card">
          <div className="table-toolbar">
            <Input.Search
              placeholder="按用户 ID / 沙箱 ID 模糊搜索，或输入节点 IP 精确查询"
              allowClear
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onSearch={applySearch}
              style={{ width: 320 }}
            />
            <RangePicker
              placeholder={["最新请求开始日期", "结束日期"]}
              value={range}
              onChange={(value) => {
                setRange(value as [Dayjs | null, Dayjs | null] | null);
                setPage(1);
              }}
            />
            <Button onClick={resetFilters}>重置</Button>
            <div className="spacer" />
            <Typography.Text type="secondary">共 {total} 条</Typography.Text>
          </div>
          <p className="hint">
            一个用户同一时间最多运行一个沙箱：每行显示用户及其当前沙箱；无用户 ID 的沙箱单独一行。
            累计请求数为该组所有沙箱之和，最新请求时间取最近一次。点击「访问详情」查看该用户（含历史沙箱）的请求记录；
            点击「状态」/「创建时间」/「最新请求时间」/「累计请求数」表头排序（降序 ↔ 升序循环）；
            「未访问」表示沙箱存在于集群但尚无访问记录；已从集群移除的沙箱不再显示（其访问记录在详情页仍可查询）；
            搜索框输入节点 IP 可查到该节点上沙箱所属的分组
          </p>
          <Table<SandboxRow>
            rowKey="uid"
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

mountPage(SummaryPage);
