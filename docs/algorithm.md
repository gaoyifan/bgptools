# Prefix Filtering Algorithm

本项目从单个 MRT/RIB 文件中筛选出特定 ASN 的前缀集合，同时剔除这些 ASN 未宣告的更具体网段。本文概述 `src/main.rs` 中主要算法的处理流程、数据结构和性能考量。

## 流程概览

1. **输入解析**  
   - 通过 `BgpkitParser` 顺序遍历 MRT 文件中的 `ANNOUNCE` 记录。  
   - `origin_asns` 与命令行传入的目标 ASN 集合匹配则计为 *include*，否则计为 *exclude*。

2. **桶式收集 (`PrefixBuckets`)**  
   - `included_v4 / included_v6`：收集所有由目标 ASN 宣告的前缀。  
   - `excluded_v4 / excluded_v6`：收集所有其他 ASN 宣告的前缀。  
   - 这里使用 `Vec<IpNet>` 而非 `IpRange`，避免 `IpRange::add` 把不同来源的前缀在早期合并，从而丢失细粒度信息。

3. **归约 (`finalize`)**  
   对 IPv4/IPv6 分别执行 `filter_range(included, excluded)`，步骤如下：

   ```text
   a. 去重：O(N) + O(M) HashSet 去重，避免重复消耗。
   b. 对每个 include 构造独立的 IpRange working 集合。
   c. 依次对所有 exclude 调用 IpRange::remove (N×M)。一旦 working 变空即提前终止。
   d. 将 working 的结果累加到 aggregate，再执行一次 simplify()。
   ```

   这种 “逐 include 处理” 的方式虽然是 N×M，但能保证：
   - 如果某个 exclude 仅覆盖 include 的一部分，我们只丢掉那部分，而不会像把 exclude 预先塞进 `IpRange` 那样整体合并成 `0.0.0.0/0`。  
   - include 自身的互相合并仅在 `aggregate.simplify()` 阶段进行，避免误删。

## 示例：223.64.0.0/10 vs 223.122.128.0/17

以实际回归样本为例：

- include：`223.64.0.0/10`（AS9808）  
- exclude：`223.122.128.0/17`（AS137872）

执行过程：

1. `working` 初始为 `{223.64.0.0/10}`。  
2. `remove(223.122.128.0/17)` 仅移除该更具体区段，`IpRange` 自动拆分并留下其他地址段。  
3. 结果 `223.64.0.0/10 - 223.122.128.0/17` 被放回 aggregate，最终输出不会包含被他人宣告的 /17。

该流程同样适用于“先 include 更具体网段后再 include supernet”的场景，因为每个 include 独立处理，supernet 不会覆盖掉后续修剪结果。

## 性能注意事项

- **去重**：RIB 中重复出现的前缀在 `dedup` 环节被 HashSet 过滤，降低 N×M 的常数。  
- **提前退出**：在 remove 循环中一旦 `working.is_empty()` 就 `break`，避免对已经空集合执行多余的 remove，实测可缩短 ~13% wall time。  
- **`IpRange::remove` vs `exclude()`**：`remove` 针对单个前缀、会根据需要自动拆分，而 `exclude()` 期望一个掩码集合。如果事先把所有 exclude 聚合在一个 `IpRange` 中，合并行为会破坏我们需要的边界，因此改用逐前缀 remove。

## 调试与验证

- `cargo test --release` 覆盖了多种 include/exclude 组合，包括回归样本。  
- 运行时可使用 `BGPT_DEBUG=1` 打印中间统计。  
- 性能基准可通过 `/usr/bin/time -l -h cargo run -r <ASN> --mrt-file <file>` 获取（参考 README）。

该算法在保留正确性的同时依赖顺序流处理，适合处理单次 RIB dump。若需要在多 ASN 或增量流量中复用，可考虑对 `PrefixBuckets` 做 sharding 或并行化，这部分留给后续设计。***

