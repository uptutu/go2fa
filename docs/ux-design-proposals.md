# go2fa GUI 设计方案

**目标版本**:v0.4.x 之后
**作用范围**:`internal/app/web/static/`(`index.html`、`app.js`)、`docs/`
**后端改动**:**无** —— `GET /api/secrets/{id}` 已能返回 issuer/account/notes/code/remaining,详情面板只是把列表里已有的数据换个地方再展示一次。

本文档覆盖两项独立的设计改进:

1. [Secret 详情面板](#1-secret-详情面板点击行展开) —— 点击单条 Secret 展开详情,展示 Account / Notes / 最新 Code
2. [主题选择器](#2-主题选择器) —— 设计师预设 6 套主题,用户可自由切换

两份方案都遵循项目现有的设计语言(液体玻璃、暗色优先、可访问性优先),改动只落在前端;实施可以分开,也可以合并。

---

## 1. Secret 详情面板(点击行展开)

### 1.1 现状与痛点

当前 secret 行(`.secret`)只展示 issuer、account、code 三件事。Account 信息挤在第二行小灰字、Notes 根本没有显示位,要么用户必须点 "Edit" 才能看到(还要切走列表上下文),要么永远看不到。

### 1.2 设计目标

| 目标 | 说明 |
|------|------|
| **零冲突** | 行点击 = 展开详情;行内 Copy / Edit / QR / 多选框必须保持原有行为不被吞 |
| **零延迟** | 详情面板的 Code 跟列表里的 Code 完全同步,不重新请求 `/api/secrets/{id}`,不引入新的 race condition |
| **不打断节奏** | 倒计时切码时,详情面板跟着跳,不会让人看到"两份不同的码" |
| **空状态优雅** | 没有 Account / Notes 的字段直接不渲染,不画 "—" 占位 |
| **键盘 + 屏幕阅读器友好** | 焦点不跳走,`aria-expanded` 同步,ESC 可关闭 |

### 1.3 交互模式选择:**行内展开 (Inline Expansion)**

**不采用弹层 (Dialog) 的理由**:
- 同一时刻只有一个 secret 展开项,弹层太重,还要管 focus trap、ESC、点遮罩关闭
- 用户大概率还要继续看列表里其他 secret 的倒计时,弹层会盖住列表
- 现有的 `.secret` 行已经有完整的 hover/click/玻璃材质视觉,展开是 row 自身的"翻牌",连贯性更好

**采用行内展开的好处**:
- 复用现有 `.glass` 材质,展开后行变大,视觉上是同一个东西的两种状态
- 列表上下文保留,用户能同时看 5 个 secret 的倒计时
- 实现简单,不需要新组件,只需要扩展 `.secret` 的 grid 行为

### 1.4 布局示意

单个 secret 行**展开后**的结构:

```
┌─ .secret (展开态) ──────────────────────────────────────────────────────┐
│ ☐ ◯  Issuer                                       [edit] [QR] [delete]   │
│     user@example.com                                                     │
│     ── 展开区(动画: max-height + opacity, 250ms) ────────────────────── │
│     ┌────────────────────────────────────────────────────────────────┐   │
│     │ ACCOUNT                                                          │   │
│     │ user@example.com                                                │   │
│     │                                                                  │   │
│     │ ALGORITHM        DIGITS        PERIOD                           │   │
│     │ SHA-1            6             30s                              │   │
│     │                                                                  │   │
│     │ CURRENT CODE                                  ⏱ 14s              │   │
│     │ ┌──────────────────────┐                                       │   │
│     │ │  1  2  3  4  5  6   │   ←跟行内 Code 一样,放大版      │   │
│     │ └──────────────────────┘                                       │   │
│     │ [ Copy code ]  [ Show QR ]  [ Refresh now ]                     │   │
│     │                                                                  │   │
│     │ NOTES                                                            │   │
│     │ recovery: +1-555-0100                                           │   │
│     │ ...                                                              │   │
│     └────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 1.5 关键设计决策

| 维度 | 决策 | 理由 |
|------|------|------|
| **触发区** | 整行点击,但 `.pick`、`.row-actions`、`.code` 三个区域 `stopPropagation` | 选中、编辑、复制必须能用,不能被"展开"吞掉 |
| **关闭方式** | ①再次点击同一行 ②点击行外任意区域 ③按 ESC | 三种关闭姿势符合 macOS / Web 习惯 |
| **Code 数据源** | 复用 `state.secrets[id].code`(或 DOM 节点的 `textContent`) | 不发新请求,不引入额外 race condition,与 v0.3.6 的 race-free 修复保持一致 |
| **倒计时同步** | 详情面板跟 row 用同一个 `tickCountdown` 帧 | 不用单独起定时器,避免"详情面板的码和列表的码不一致" |
| **空字段处理** | 字段不渲染(连标题都不显示) | 少即是多,没信息就别让人看到 "—" |
| **多选模式** | `body.selecting` 下,行点击只切换选中,不展开 | 多选场景下展开会打架 |
| **焦点管理** | 展开时焦点留在行(不跳到面板) | 不偷焦点,与现有 focus ring 配合;屏幕阅读器读 `aria-expanded` |
| **动画** | `grid-template-rows: 0fr → 1fr` + opacity,250ms `cubic-bezier(.2,.8,.2,1)` | 不抖布局、不触发 CLS,符合 transform/opacity 性能原则 |
| **移动端** | 整行可点,展开后内容垂直堆叠;不另起 bottom sheet | 桌面 GUI 优先,但不破坏手机 web 体验 |

### 1.6 CSS 增量

需要追加到 `internal/app/web/static/index.html` 的 `<style>` 末尾:

```css
/* -------- Secret detail panel -------- */
.secret {
  cursor: pointer;
  -webkit-tap-highlight-color: transparent;
}
.secret .who,
.secret .code-wrap,
.secret .ring {
  pointer-events: none; /* 整行点击,不重复触发内部 */
}
.secret .pick,
.secret .row-actions,
.secret .code {
  pointer-events: auto; /* 这三个保留自身交互 */
}

/* 展开态: grid 整体从 5 列切回单列堆叠 */
.secret.expanded {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.secret.expanded .who,
.secret.expanded .code-wrap,
.secret.expanded .ring,
.secret.expanded .row-actions,
.secret.expanded .pick {
  pointer-events: auto;
}
.secret.expanded .pick { opacity: 1; }

/* 详情区(grid-template-rows 动画,不抖布局) */
.secret .detail {
  display: grid;
  grid-template-rows: 0fr;
  opacity: 0;
  transition: grid-template-rows .25s cubic-bezier(.2,.8,.2,1), opacity .2s;
}
.secret .detail > .detail-inner {
  overflow: hidden;
  min-height: 0;
}
.secret.expanded .detail {
  grid-template-rows: 1fr;
  opacity: 1;
}

.detail-grid {
  display: grid;
  gap: 16px;
  padding: 16px 4px 4px;
  border-top: 1px dashed var(--border);
}
.detail-grid .label {
  font-size: 11px;
  color: var(--text-faint);
  text-transform: uppercase;
  letter-spacing: .5px;
  font-weight: 600;
  margin-bottom: 4px;
}
.detail-grid .account-big {
  font-family: var(--mono);
  font-size: 14px;
  color: var(--text);
}
.detail-grid .meta-row {
  display: flex;
  gap: 22px;
  flex-wrap: wrap;
}
.detail-grid .meta-row > div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.detail-grid .meta-row .value {
  font-size: 13px;
  color: var(--text);
  font-variant-numeric: tabular-nums;
}
.detail-code-row {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.detail-code {
  font-family: var(--mono);
  font-size: 38px;
  letter-spacing: 4px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  color: var(--accent);
  padding: 14px 22px;
  background: linear-gradient(180deg,
    color-mix(in srgb, var(--accent) 14%, transparent),
    color-mix(in srgb, var(--accent) 4%, transparent));
  border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
  border-radius: var(--radius-sm);
  cursor: pointer;
  user-select: all;
  text-shadow: 0 0 22px color-mix(in srgb, var(--accent) 45%, transparent);
  transition: border-color .2s, box-shadow .2s, transform .15s;
}
.detail-code:hover {
  border-color: var(--accent);
  transform: translateY(-1px);
  box-shadow:
    0 0 0 1px color-mix(in srgb, var(--accent) 22%, transparent),
    0 0 28px color-mix(in srgb, var(--accent) 30%, transparent);
}
.detail-code.copied {
  background: color-mix(in srgb, var(--good) 22%, transparent);
  border-color: var(--good);
  color: var(--good);
}
.detail-code .timer {
  font-family: system-ui, sans-serif;
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0;
  color: var(--text-dim);
  text-shadow: none;
  margin-left: 4px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.detail-code .timer svg { width: 12px; height: 12px; }
.detail-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.detail-notes {
  white-space: pre-wrap;
  color: var(--text);
  font-size: 13px;
  line-height: 1.55;
  padding: 10px 14px;
  background: var(--glass-2);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
}
.secret.expanded {
  background: var(--glass-2);
  box-shadow: var(--topline), 0 14px 28px -10px rgba(0,0,0,0.45),
    0 4px 14px -8px color-mix(in srgb, var(--accent) 18%, transparent);
}

@media (max-width: 640px) {
  .detail-code { font-size: 30px; padding: 12px 18px; }
  .detail-grid .meta-row { gap: 14px; }
}
```

### 1.7 HTML 模板增量

详情面板的 DOM 结构。需要在 `app.js` 的 `updateRow()` 或行创建函数里追加:

```html
<div class="detail">
  <div class="detail-inner">
    <div class="detail-grid">
      <!-- 只有有 account 才渲染 -->
      <div class="detail-field-account">
        <div class="label" data-i18n="detail_account">Account</div>
        <div class="account-big"></div>
      </div>

      <div class="meta-row">
        <div><span class="label" data-i18n="detail_algo">Algorithm</span><span class="value"></span></div>
        <div><span class="label" data-i18n="detail_digits">Digits</span><span class="value"></span></div>
        <div><span class="label" data-i18n="detail_period">Period</span><span class="value"></span></div>
      </div>

      <div class="detail-code-row">
        <div class="detail-code" tabindex="0" role="button" aria-label="">
          <span class="code-text"></span>
        </div>
        <span class="timer"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg><span class="sec"></span>s</span>
        <div class="detail-actions">
          <button class="btn copy-btn" data-i18n="copy">Copy</button>
          <button class="btn qr-btn" data-i18n="qr_show">Show QR</button>
          <button class="btn refresh-btn" data-i18n="refresh_now">Refresh</button>
        </div>
      </div>

      <!-- 只有有 notes 才渲染 -->
      <div class="detail-field-notes">
        <div class="label" data-i18n="detail_notes">Notes</div>
        <div class="detail-notes"></div>
      </div>
    </div>
  </div>
</div>
```

### 1.8 JS 增量

```js
// 状态:当前展开的 secret id,全局唯一
let expandedId = null;

// 1) 行渲染:updateRow() 在创建行 DOM 时,额外填充 detail 区域字段
//    - 已有 .who/.issuer/.account 已经在 row 内,详情面板只补全 meta、code、notes
//    - 用现有的 s.algorithm / s.digits / s.period / s.notes 直接读
function fillDetail(row, s) {
  const det = row.querySelector('.detail');
  if (!det) return;

  // Account 字段:有就显示,没有整块隐藏
  const accField = det.querySelector('.detail-field-account');
  if (s.account && s.account.trim()) {
    accField.hidden = false;
    accField.querySelector('.account-big').textContent = s.account;
  } else {
    accField.hidden = true;
  }

  // Meta row:始终显示(算法/位数/周期是 secret 自带属性)
  const metaValues = det.querySelectorAll('.meta-row > div .value');
  metaValues[0].textContent = s.algorithm;
  metaValues[1].textContent = String(s.digits);
  metaValues[2].textContent = s.period + 's';

  // Code + 倒计时:跟 row 主体共享 tickCountdown / refreshSecrets
  det.querySelector('.detail-code .code-text').textContent = s.code;
  det.querySelector('.detail-code .timer .sec').textContent = s.remaining;

  // Notes 字段:有就显示
  const notesField = det.querySelector('.detail-field-notes');
  if (s.notes && s.notes.trim()) {
    notesField.hidden = false;
    notesField.querySelector('.detail-notes').textContent = s.notes;
  } else {
    notesField.hidden = true;
  }
}

// 2) 点击委托:整行点击展开/收起,但子控件不展开
$('#secrets').addEventListener('click', (e) => {
  const row = e.target.closest('.secret');
  if (!row) return;
  // 子控件(多选框、行动按钮、Code 按钮)不触发展开
  if (e.target.closest('.pick, .row-actions, .code')) return;
  // 多选模式下不展开
  if (document.body.classList.contains('selecting')) return;
  toggleExpanded(row.dataset.id);
});

function toggleExpanded(id) {
  expandedId = expandedId === id ? null : id;
  $$('.secret').forEach(r => {
    const open = r.dataset.id === expandedId;
    r.classList.toggle('expanded', open);
    r.setAttribute('aria-expanded', String(open));
  });
}

// 3) ESC 关闭
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && expandedId) {
    toggleExpanded(expandedId);
  }
});

// 4) 倒计时同步:在现有 tickCountdown() / refreshSecrets() 里多更新一行
//    现状:tickCountdown 更新 row 的 textContent 和 SVG circle
//    新增:同步更新详情面板的 .timer 和 .detail-code .code-text
function syncDetailTick(row, s) {
  if (!row.classList.contains('expanded')) return;
  const det = row.querySelector('.detail');
  if (!det) return;
  const codeEl = det.querySelector('.detail-code .code-text');
  const timerEl = det.querySelector('.detail-code .timer .sec');
  if (codeEl) codeEl.textContent = s.code;
  if (timerEl) timerEl.textContent = s.remaining;
}
// 然后在 tickCountdown 主循环里调用: syncDetailTick(row, s);
// 在 refreshSecrets 拿到新 secrets 后,对每个展开的 row 也调用: syncDetailTick(row, newS);

// 5) 详情面板的 Copy 按钮:复用现有 copyCode() 逻辑
//    推荐抽出一个 copyCodeFor(secretId, buttonEl) 共享函数
//    详情面板 .detail-code 也响应 click → copyCodeFor(row.dataset.id, target)

// 6) 详情面板的 Refresh 按钮:发 /api/code?id=xxx,刷新当前 code
//    按钮绑定在 fillDetail() 里行创建时一次完成
```

### 1.9 可访问性

| 项 | 处理 |
|----|------|
| 触发 | `.secret` 是 `<li role="button" tabindex="0" aria-expanded="false">` |
| 键盘 | Enter / Space 触发展开(同 click) |
| ESC | 关闭展开 |
| 屏幕阅读器 | `aria-expanded` 同步;展开时读 "Expanded" |
| 焦点 | 展开后焦点留在行,不跳到详情;屏幕阅读器读 `aria-expanded` 状态 |
| 减少动效 | `@media (prefers-reduced-motion: reduce)` 下 `grid-template-rows` 动画关掉,直接 display 切换 |

### 1.10 i18n 新增键

```js
en: {
  detail_account: 'Account',
  detail_algo: 'Algorithm',
  detail_digits: 'Digits',
  detail_period: 'Period',
  detail_code_aria: 'Copy current code, {digits} digits',
  detail_notes: 'Notes',
  qr_show: 'Show QR',
  refresh_now: 'Refresh',
},
zh: {
  detail_account: '账号',
  detail_algo: '算法',
  detail_digits: '位数',
  detail_period: '周期',
  detail_code_aria: '复制当前验证码,共 {digits} 位',
  detail_notes: '备注',
  qr_show: '显示二维码',
  refresh_now: '立即刷新',
}
```

### 1.11 实施清单

- [ ] `index.html` `<style>` 末尾追加 1.6 节 CSS
- [ ] `app.js` `updateRow()` / 行创建函数里追加 `.detail` DOM 填充
- [ ] `app.js` 新增 `expandedId` 状态 + 委托点击 + ESC
- [ ] `app.js` `tickCountdown()` / `refreshSecrets()` 调用 `syncDetailTick()`
- [ ] `app.js` 详情面板 Copy / QR / Refresh 按钮绑事件
- [ ] i18n dict 加 6 个 key(en + zh)
- [ ] 测:展开/收起、ESC、空字段、多选模式、移动端
- [ ] 测:倒计时切码时详情面板是否同步

---

## 2. 主题选择器

### 2.1 现状与痛点

当前只有一个主题:亮绿色 (`--accent: #7cf7b1`) + 暗色优先 + 液体玻璃材质。喜欢这个调子的用户没意见,但:
- 用户在不同环境(夜晚/白天/办公/咖啡馆)需要不同对比度
- 现有 `prefers-color-scheme: light` 映射是写死的,无法手动覆盖
- 没有"低调商务"、"极简开发者"等差异化选择

### 2.2 设计目标

| 目标 | 说明 |
|------|------|
| **6 套设计师预设** | 覆盖暗/亮/冷/暖/极简 5 个维度,各有不同玻璃强度和 blob 色调 |
| **CSS 变量驱动** | 只换 `:root` 下那一组 token,组件样式不动 |
| **首屏不闪** | `<head>` 内联同步脚本,DOM 渲染前完成属性写入 |
| **持久化** | `localStorage`,跨会话保留 |
| **键盘 + 屏幕阅读器友好** | 弹层有 `role="dialog"`、ESC 关闭、焦点回到触发按钮 |

### 2.3 6 套主题

| ID | 名称 | 风格定位 | 主色 |
|----|------|----------|------|
| `aurora` | **Aurora Mint**(默认) | 液体玻璃 / 薄荷绿冷调 / 暗色为主 | `#7cf7b1` |
| `obsidian` | **Obsidian Slate** | 极简暗色 / 冷灰蓝 / 偏开发者工具 | `#7dd3fc` |
| `dusk` | **Dusk Violet** | 紫粉黄昏 / 中等饱和 / 玻璃柔光 | `#c4a7ff` |
| `paper` | **Paper Light** | 纸张浅色 / 低对比暖白 / 单色细描边 | `#2f7d4f` |
| `ember` | **Ember Sunset** | 暗橙琥珀 / 暖色高对比 / 玻璃略厚 | `#ff9966` |
| `mono` | **Mono Editorial** | 纯黑白灰 / 高对比 / 玻璃退化为细描边 | `#9aa39a` |

主题对比一览(预期视觉):

- **Aurora**:夜店感,绿色高光 + 蓝青副色,blob 多彩
- **Obsidian**:冷静专业,蓝灰主导,blob 几乎不可见
- **Dusk**:浪漫文艺,紫粉渐变,blob 浓
- **Paper**:白天办公,暖白底 + 深绿点缀,无 blob
- **Ember**:夜晚温暖,橙黄高光,blob 暖色
- **Mono**:极简主义,纯灰阶,blob 关掉,玻璃退化为细描边

### 2.4 关键设计决策

| 维度 | 决策 | 理由 |
|------|------|------|
| **存储位置** | `localStorage['go2fa.theme']` | 简单、跨会话、不需要后端配合 |
| **首屏防闪** | `<head>` 内联同步脚本 | 不阻塞首屏渲染,渲染前属性已写入 |
| **切换粒度** | 替换 `:root` 上整组 token | 现有样式 100% 用 token,不需改组件 |
| **popover 位置** | 贴 header 右下角 | 跟 lang-switch 同一区域,符合用户对设置入口的预期 |
| **popover 形态** | 自定义 popover(非模态) | 不阻挡列表,允许快速切换多个主题对比 |
| **键盘交互** | Enter/Space 选中;ESC 关闭 | 与 macOS / Web 弹层习惯一致 |
| **关闭策略** | 点 popover 外、ESC、再次点主题按钮 | 三种关闭姿势 |
| **背景 blob** | `mono` 主题隐藏;其他主题保留,只换色调 | Mono 主题追求极简,blob 是噪声 |
| **焦点回归** | ESC 关闭后焦点回到 theme 按钮 | 标准 ARIA 弹层模式 |
| **触摸目标** | 主题卡片 ≥ 44×44px | 满足 Apple HIG / Material 标准 |
| **降低动效** | `prefers-reduced-motion: reduce` 下 popover 入场动画关掉 | 与现有 reduce-motion 策略一致 |

### 2.5 CSS —— 用 `[data-theme]` 驱动

把 `:root` 的 token 保留为 `aurora`(默认),其余 5 套挂在 `[data-theme="xxx"]` 下,完全平铺。

**做法**:
1. 把 `:root` 改成 `:root, [data-theme="aurora"]`,保证默认主题一致
2. 把 `@media (prefers-color-scheme: light) :root { ... }` 改成 `@media (prefers-color-scheme: light) :root:not([data-theme]), [data-theme="aurora"] { ... }` —— 只有未指定主题或显式选 aurora 时才跟系统
3. 其他主题自己定义浅色映射(如果需要)

#### 2.5.1 token 结构

```css
:root,
[data-theme="aurora"] {
  color-scheme: dark;
  --bg: #06080c;
  --glass: rgba(255,255,255,0.06);
  --glass-2: rgba(255,255,255,0.12);
  --border: rgba(255,255,255,0.14);
  --border-strong: rgba(255,255,255,0.28);
  --topline: inset 0 1px 0 rgba(255,255,255,0.18), inset 0 -1px 0 rgba(0,0,0,0.18);
  --refract:
    conic-gradient(from calc(var(--mx,50%) * 1deg) at calc(var(--mx,50%)) calc(var(--my,30%)),
      rgba(255,255,255,0) 0deg,
      rgba(255,255,255,0.18) 30deg,
      rgba(255,255,255,0) 60deg,
      rgba(255,255,255,0) 300deg,
      rgba(255,255,255,0.14) 330deg,
      rgba(255,255,255,0) 360deg);
  --dialog-bg: rgba(13,17,16,0.62);
  --text: #eef4f0;
  --text-dim: #a7b6ae;
  --text-faint: #6f8078;
  --accent: #7cf7b1;
  --accent-2: #4dd9ff;
  --good: #4ade80;
  --warn: #facc15;
  --danger: #ff6b6b;
  --shadow:
    0 1px 0 rgba(255,255,255,0.06) inset,
    0 24px 48px -12px rgba(0,0,0,0.55),
    0 8px 20px -8px rgba(124,247,177,0.10);
  --shadow-lg:
    0 1px 0 rgba(255,255,255,0.10) inset,
    0 40px 80px -20px rgba(0,0,0,0.65),
    0 16px 40px -16px rgba(77,217,255,0.20);
  --blur: blur(28px) saturate(180%);
  --focus: 0 0 0 2px var(--bg), 0 0 0 4px var(--accent);
}

/* Obsidian —— 冷灰蓝,玻璃更克制,blob 几乎不可见 */
[data-theme="obsidian"] {
  color-scheme: dark;
  --bg: #0c1014;
  --glass: rgba(255,255,255,0.04);
  --glass-2: rgba(255,255,255,0.08);
  --border: rgba(255,255,255,0.10);
  --border-strong: rgba(255,255,255,0.22);
  --topline: inset 0 1px 0 rgba(255,255,255,0.10), inset 0 -1px 0 rgba(0,0,0,0.22);
  --dialog-bg: rgba(12,18,22,0.62);
  --text: #e4ecf3;
  --text-dim: #8b9ba8;
  --text-faint: #5a6878;
  --accent: #7dd3fc;
  --accent-2: #818cf8;
  --good: #34d399;
  --warn: #fbbf24;
  --danger: #f87171;
  --shadow:
    0 1px 0 rgba(255,255,255,0.04) inset,
    0 24px 48px -12px rgba(0,0,0,0.55),
    0 8px 20px -8px rgba(125,211,252,0.10);
  --shadow-lg:
    0 1px 0 rgba(255,255,255,0.08) inset,
    0 40px 80px -20px rgba(0,0,0,0.65),
    0 16px 40px -16px rgba(129,140,248,0.18);
  --blur: blur(28px) saturate(140%);
}
[data-theme="obsidian"] .b1,
[data-theme="obsidian"] .b2,
[data-theme="obsidian"] .b3 { opacity: 0.30; }

/* Dusk Violet */
[data-theme="dusk"] {
  color-scheme: dark;
  --bg: #0d0b18;
  --glass: rgba(255,255,255,0.07);
  --glass-2: rgba(255,255,255,0.13);
  --border: rgba(255,255,255,0.12);
  --border-strong: rgba(255,255,255,0.24);
  --dialog-bg: rgba(18,12,28,0.62);
  --text: #f1ebff;
  --text-dim: #a99ec4;
  --text-faint: #6e6485;
  --accent: #c4a7ff;
  --accent-2: #ff9bcb;
  --good: #86efac;
  --warn: #fcd34d;
  --danger: #fb7185;
  --shadow:
    0 1px 0 rgba(255,255,255,0.06) inset,
    0 24px 48px -12px rgba(0,0,0,0.55),
    0 8px 20px -8px rgba(196,167,255,0.12);
  --shadow-lg:
    0 1px 0 rgba(255,255,255,0.10) inset,
    0 40px 80px -20px rgba(0,0,0,0.65),
    0 16px 40px -16px rgba(255,155,203,0.20);
  --blur: blur(30px) saturate(180%);
}
[data-theme="dusk"] .b1 { background: radial-gradient(circle, rgba(196,167,255,0.35), transparent 70%); }
[data-theme="dusk"] .b2 { background: radial-gradient(circle, rgba(255,155,203,0.30), transparent 70%); }
[data-theme="dusk"] .b3 { background: radial-gradient(circle, rgba(140,120,255,0.22), transparent 70%); }

/* Paper Light —— 单套亮色 */
[data-theme="paper"] {
  color-scheme: light;
  --bg: #f3efe7;
  --glass: rgba(255,255,255,0.55);
  --glass-2: rgba(255,255,255,0.78);
  --border: rgba(20,40,32,0.12);
  --border-strong: rgba(20,40,32,0.24);
  --topline: inset 0 1px 0 rgba(255,255,255,0.9), inset 0 -1px 0 rgba(20,40,32,0.06);
  --refract:
    conic-gradient(from calc(var(--mx,50%) * 1deg) at calc(var(--mx,50%)) calc(var(--my,30%)),
      rgba(255,255,255,0) 0deg,
      rgba(255,255,255,0.45) 30deg,
      rgba(255,255,255,0) 60deg,
      rgba(255,255,255,0) 300deg,
      rgba(255,255,255,0.40) 330deg,
      rgba(255,255,255,0) 360deg);
  --dialog-bg: rgba(255,255,255,0.72);
  --text: #1f2a23;
  --text-dim: #4d5e54;
  --text-faint: #7a8a82;
  --accent: #2f7d4f;
  --accent-2: #1a4d6e;
  --good: #16a34a;
  --warn: #b45309;
  --danger: #b91c1c;
  --shadow:
    0 1px 0 rgba(255,255,255,0.85) inset,
    0 24px 48px -16px rgba(30,60,45,0.18),
    0 8px 20px -10px rgba(47,125,79,0.14);
  --shadow-lg:
    0 1px 0 rgba(255,255,255,0.95) inset,
    0 40px 80px -24px rgba(30,60,45,0.26),
    0 16px 40px -20px rgba(47,125,79,0.18);
  --blur: blur(24px) saturate(150%);
}
[data-theme="paper"] .b1 { background: radial-gradient(circle, rgba(47,125,79,0.20), transparent 70%); }
[data-theme="paper"] .b2 { background: radial-gradient(circle, rgba(26,77,110,0.15), transparent 70%); }
[data-theme="paper"] .b3 { background: radial-gradient(circle, rgba(180,83,9,0.10), transparent 70%); }
[data-theme="paper"] .b1,
[data-theme="paper"] .b2,
[data-theme="paper"] .b3 { opacity: 0.40; }

/* Ember Sunset */
[data-theme="ember"] {
  color-scheme: dark;
  --bg: #140a08;
  --glass: rgba(255,255,255,0.05);
  --glass-2: rgba(255,255,255,0.10);
  --border: rgba(255,255,255,0.12);
  --border-strong: rgba(255,255,255,0.22);
  --dialog-bg: rgba(28,16,12,0.62);
  --text: #fbecd9;
  --text-dim: #b89a82;
  --text-faint: #826452;
  --accent: #ff9966;
  --accent-2: #ffb86b;
  --good: #fbbf24;
  --warn: #f59e0b;
  --danger: #ef4444;
  --shadow:
    0 1px 0 rgba(255,255,255,0.06) inset,
    0 24px 48px -12px rgba(0,0,0,0.55),
    0 8px 20px -8px rgba(255,153,102,0.14);
  --shadow-lg:
    0 1px 0 rgba(255,255,255,0.08) inset,
    0 40px 80px -20px rgba(0,0,0,0.65),
    0 16px 40px -16px rgba(255,184,107,0.20);
  --blur: blur(30px) saturate(160%);
}
[data-theme="ember"] .b1 { background: radial-gradient(circle, rgba(255,153,102,0.35), transparent 70%); }
[data-theme="ember"] .b2 { background: radial-gradient(circle, rgba(255,184,107,0.28), transparent 70%); }
[data-theme="ember"] .b3 { background: radial-gradient(circle, rgba(245,158,11,0.22), transparent 70%); }

/* Mono —— 玻璃退化为细描边,blob 关掉 */
[data-theme="mono"] {
  color-scheme: dark;
  --bg: #0a0a0a;
  --glass: rgba(255,255,255,0.02);
  --glass-2: rgba(255,255,255,0.05);
  --border: rgba(255,255,255,0.18);
  --border-strong: rgba(255,255,255,0.32);
  --topline: inset 0 1px 0 rgba(255,255,255,0.08);
  --refract: none;
  --dialog-bg: rgba(15,15,15,0.85);
  --text: #f0f0f0;
  --text-dim: #a0a0a0;
  --text-faint: #6a6a6a;
  --accent: #c0c6c0;
  --accent-2: #9aa39a;
  --good: #c0c6c0;
  --warn: #c0c6c0;
  --danger: #ff6b6b;
  --shadow:
    0 1px 0 rgba(255,255,255,0.04) inset,
    0 2px 0 rgba(0,0,0,0.55);
  --shadow-lg:
    0 1px 0 rgba(255,255,255,0.06) inset,
    0 4px 0 rgba(0,0,0,0.55);
  --blur: blur(0);
}
@media (prefers-color-scheme: light) {
  [data-theme="mono"] {
    color-scheme: light;
    --bg: #ffffff;
    --glass: rgba(0,0,0,0.02);
    --glass-2: rgba(0,0,0,0.04);
    --border: rgba(0,0,0,0.18);
    --border-strong: rgba(0,0,0,0.32);
    --text: #0a0a0a;
    --text-dim: #555555;
    --text-faint: #8a8a8a;
  }
}
[data-theme="mono"] .b1,
[data-theme="mono"] .b2,
[data-theme="mono"] .b3 { display: none; }
[data-theme="mono"] .glass::before,
[data-theme="mono"] .glass::after { display: none; }
```

#### 2.5.2 把现有 `prefers-color-scheme: light` 块改写

```css
/* 仅当用户未选主题或显式选 aurora 时,跟系统浅色 */
@media (prefers-color-scheme: light) {
  :root:not([data-theme]),
  [data-theme="aurora"] {
    color-scheme: light;
    --bg: #dde6e1;
    --glass: rgba(255,255,255,0.55);
    --glass-2: rgba(255,255,255,0.78);
    --border: rgba(20,40,32,0.12);
    --border-strong: rgba(20,40,32,0.24);
    --topline: inset 0 1px 0 rgba(255,255,255,0.9), inset 0 -1px 0 rgba(20,40,32,0.08);
    --dialog-bg: rgba(255,255,255,0.72);
    --text: #0f1d16;
    --text-dim: #46594f;
    --text-faint: #75867d;
    --accent: #0e9e63;
    --accent-2: #0b7a4d;
    --shadow:
      0 1px 0 rgba(255,255,255,0.85) inset,
      0 24px 48px -16px rgba(30,60,45,0.22),
      0 8px 20px -10px rgba(14,158,99,0.14);
    --shadow-lg:
      0 1px 0 rgba(255,255,255,0.95) inset,
      0 40px 80px -24px rgba(30,60,45,0.30),
      0 16px 40px -20px rgba(14,158,99,0.20);
  }
}
```

> **重要**:把 `@media (prefers-color-scheme: light)` 里 `scrim` 背景和 `.field input` 浅色映射也按相同规则改写,确保主题切换在显式选择时不受系统色影响。

### 2.6 HTML 增量

#### 2.6.1 `<head>` 内联防闪脚本

放在 `<head>` 内、所有样式表之前:

```html
<script>
  try {
    var t = localStorage.getItem('go2fa.theme') || 'aurora';
    document.documentElement.setAttribute('data-theme', t);
  } catch (_) {}
</script>
```

#### 2.6.2 header 加主题按钮

放在 `.lang-switch` 之前:

```html
<button id="theme-btn" class="btn ghost" type="button" aria-haspopup="dialog" aria-expanded="false" aria-label="Theme" title="Theme">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14" aria-hidden="true">
    <circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18"/>
  </svg>
  <span id="theme-current">Aurora</span>
</button>
```

#### 2.6.3 popover 容器

放在 `.app` 末尾、所有 dialog 之前:

```html
<div id="theme-pop" class="theme-pop" hidden role="dialog" aria-label="Choose theme" aria-modal="false">
  <div class="theme-grid">
    <button class="theme-card" type="button" data-theme="aurora" aria-pressed="true">
      <span class="swatch" style="--swatch:#7cf7b1"></span>
      <span class="name">Aurora Mint</span>
      <span class="hint">Default</span>
    </button>
    <button class="theme-card" type="button" data-theme="obsidian" aria-pressed="false">
      <span class="swatch" style="--swatch:#7dd3fc"></span>
      <span class="name">Obsidian Slate</span>
      <span class="hint">Cool</span>
    </button>
    <button class="theme-card" type="button" data-theme="dusk" aria-pressed="false">
      <span class="swatch" style="--swatch:#c4a7ff"></span>
      <span class="name">Dusk Violet</span>
      <span class="hint">Warm</span>
    </button>
    <button class="theme-card" type="button" data-theme="paper" aria-pressed="false">
      <span class="swatch" style="--swatch:#2f7d4f"></span>
      <span class="name">Paper Light</span>
      <span class="hint">Daytime</span>
    </button>
    <button class="theme-card" type="button" data-theme="ember" aria-pressed="false">
      <span class="swatch" style="--swatch:#ff9966"></span>
      <span class="name">Ember Sunset</span>
      <span class="hint">Cozy</span>
    </button>
    <button class="theme-card" type="button" data-theme="mono" aria-pressed="false">
      <span class="swatch" style="--swatch:#9aa39a"></span>
      <span class="name">Mono Editorial</span>
      <span class="hint">Minimal</span>
    </button>
  </div>
</div>
```

### 2.7 popover CSS

```css
/* -------- Theme picker popover -------- */
.theme-pop {
  position: fixed;
  top: 64px;
  right: 18px;
  width: 296px;
  padding: 10px;
  background: var(--dialog-bg);
  backdrop-filter: var(--blur);
  -webkit-backdrop-filter: var(--blur);
  border: 1px solid var(--border-strong);
  border-radius: 18px;
  box-shadow: var(--shadow-lg);
  z-index: 80;
  transform-origin: top right;
  animation: pop-in .22s cubic-bezier(.2, .9, .3, 1.2);
}
@keyframes pop-in {
  from { opacity: 0; transform: scale(0.94) translateY(-4px); }
  to { opacity: 1; transform: none; }
}
.theme-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.theme-card {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  min-height: 44px; /* 满足触摸目标 */
  border-radius: 12px;
  background: var(--glass);
  border: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 13px;
  text-align: left;
  cursor: pointer;
  transition: background .2s, border-color .2s, color .2s, transform .15s;
}
.theme-card:hover {
  background: var(--glass-2);
  color: var(--text);
  border-color: var(--border-strong);
  transform: translateY(-1px);
}
.theme-card[aria-pressed="true"] {
  border-color: var(--accent);
  background: color-mix(in srgb, var(--accent) 14%, var(--glass));
  box-shadow:
    var(--topline),
    0 0 0 1px color-mix(in srgb, var(--accent) 22%, transparent) inset;
  color: var(--text);
}
.theme-card .swatch {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  flex-shrink: 0;
  background: var(--swatch);
  box-shadow: 0 0 8px var(--swatch);
}
.theme-card .name { font-weight: 600; }
.theme-card .hint {
  margin-left: auto;
  font-size: 11px;
  color: var(--text-faint);
}
.theme-card[aria-pressed="true"] .hint { color: var(--accent); }
@media (prefers-reduced-motion: reduce) {
  .theme-pop { animation: none; }
}
```

### 2.8 JS

```js
// -------- Theme picker --------
const THEMES = ['aurora', 'obsidian', 'dusk', 'paper', 'ember', 'mono'];
const THEME_LABELS = {
  aurora: 'Aurora',
  obsidian: 'Obsidian',
  dusk: 'Dusk',
  paper: 'Paper',
  ember: 'Ember',
  mono: 'Mono',
};
const root = document.documentElement;
const themeBtn = $('#theme-btn');
const themePop = $('#theme-pop');
const themeCurrent = $('#theme-current');

function applyTheme(id, { persist = true } = {}) {
  if (!THEMES.includes(id)) id = 'aurora';
  root.setAttribute('data-theme', id);
  if (persist) {
    try { localStorage.setItem('go2fa.theme', id); } catch (_) {}
  }
  themeCurrent.textContent = THEME_LABELS[id];
  $$('.theme-card').forEach(c =>
    c.setAttribute('aria-pressed', String(c.dataset.theme === id))
  );
}

// 首次应用:data-theme 已由 <head> 防闪脚本设置过;这里只同步 UI 状态
applyTheme(root.getAttribute('data-theme') || 'aurora', { persist: false });

themeBtn.addEventListener('click', () => {
  const open = !themePop.hidden;
  themePop.hidden = open;
  themeBtn.setAttribute('aria-expanded', String(!open));
});
document.addEventListener('click', (e) => {
  if (themePop.hidden) return;
  if (e.target.closest('#theme-pop, #theme-btn')) return;
  themePop.hidden = true;
  themeBtn.setAttribute('aria-expanded', 'false');
});
themePop.addEventListener('click', (e) => {
  const c = e.target.closest('.theme-card');
  if (!c) return;
  applyTheme(c.dataset.theme);
  themePop.hidden = true;
  themeBtn.setAttribute('aria-expanded', 'false');
  themeBtn.focus();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !themePop.hidden) {
    themePop.hidden = true;
    themeBtn.setAttribute('aria-expanded', 'false');
    themeBtn.focus();
  }
});
```

### 2.9 可访问性

| 项 | 处理 |
|----|------|
| 触发 | `<button aria-haspopup="dialog" aria-expanded>` |
| 弹层 | `role="dialog"` + `aria-label` |
| 选中状态 | `aria-pressed="true"` 在当前主题卡上 |
| 键盘 | Tab 在 6 张卡间切换,Enter/Space 选中,ESC 关闭 |
| 焦点回归 | ESC 关闭后焦点回到 theme 按钮 |
| 触摸目标 | 主题卡片 ≥ 44×44px |
| 减少动效 | `prefers-reduced-motion: reduce` 下 popover 入场动画关掉 |
| 颜色对比 | 所有主题的 `--text` / `--bg` 对比度 ≥ 4.5:1(需实测) |
| 不只靠颜色 | 选中态用边框 + 文字 hint,不只用色块高亮 |

### 2.10 实施清单

- [ ] `index.html` `<head>` 加防闪同步脚本
- [ ] `index.html` `<style>` 块:把 `:root` 改为 `:root, [data-theme="aurora"]`,补全 5 套主题 token
- [ ] `index.html` `<style>` 块:`@media (prefers-color-scheme: light)` 改用 `:root:not([data-theme]), [data-theme="aurora"]`
- [ ] `index.html` header 加主题按钮
- [ ] `index.html` `.app` 末尾加 theme-pop 容器
- [ ] `index.html` `<style>` 末尾加 popover + theme-card CSS
- [ ] `app.js` 加 `THEMES`、`applyTheme()`、点击 / ESC / outside-click 关闭逻辑
- [ ] 测:6 套主题切换、刷新页面后保留、与其他弹层不冲突、键盘可访问
- [ ] 测:`prefers-reduced-motion: reduce` 下无入场动画
- [ ] 测:暗 / 亮系统下,显式选其他主题不会被系统色覆盖

---

## 3. 验证清单(发布前)

| 项 | 标准 |
|----|------|
| 详情面板展开/收起 | 流畅、无布局抖动 |
| 详情面板 Code 同步 | 切码时跟列表完全一致 |
| 详情面板空字段 | Account / Notes 缺失时不渲染占位 |
| 多选模式 | `body.selecting` 下点击行不展开 |
| 移动端 | ≤ 640px 整行可点、详情区正确堆叠 |
| 键盘 | Enter / Space 展开,ESC 关闭,焦点正确 |
| 屏幕阅读器 | `aria-expanded` 同步,语义化标签齐全 |
| 主题切换 | 6 套主题都能切,样式一致可用 |
| 首屏防闪 | 刷新页面看不到默认主题到选定主题的过渡 |
| 主题持久化 | 关闭浏览器后再打开仍是上次选择 |
| 主题 popover | 3 种关闭方式都能用、键盘可达 |
| 主题对比度 | 每个主题的正文文字对比度 ≥ 4.5:1 |
| 减少动效 | `prefers-reduced-motion: reduce` 下所有动画 0.01ms |
| 现有功能不退化 | Copy / Edit / QR / 多选 / 导出 / 锁 / 主题切换 全部仍能用 |
| 构建 | `make build` 绿,`make test` 全过 |

---

## 4. 排期建议

| 阶段 | 内容 | 预估 |
|------|------|------|
| v0.4.0 | 主题选择器(方案 2) | 1 个 PR,约 150 行 |
| v0.4.1 | Secret 详情面板(方案 1) | 1 个 PR,约 120 行 |
| v0.4.2 | 体验打磨 + 文档 + 截图 | 0.5 个 PR |

两个方案可以分开做,先后顺序可以换。**建议先做主题选择器** —— 它纯前端、不依赖详情面板,改完可以单独看到效果,也不会被后续详情面板的渲染压力影响。