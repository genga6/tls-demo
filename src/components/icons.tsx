/**
 * 画面で使う絵記号。
 *
 * 絵文字は環境ごとに形も色も変わってしまうので、必要なものだけ自分で描いている。
 * すべて 24×24 の枠・線は currentColor なので、置いた場所の文字色に馴染む。
 */

import type { ReactNode } from "react";

function Icon({ children, size = 20 }: { children: ReactNode; size?: number }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export type IconProps = { size?: number };

/** クライアント側。ブラウザのウィンドウ。 */
export function IconBrowser({ size }: IconProps) {
  return (
    <Icon size={size}>
      <rect x="2.5" y="4" width="19" height="16" rx="2.5" />
      <path d="M2.5 8.5h19" />
      <circle cx="5.6" cy="6.2" r="0.7" fill="currentColor" stroke="none" />
      <circle cx="8" cy="6.2" r="0.7" fill="currentColor" stroke="none" />
      <path d="M6 12.5h8M6 16h5" />
    </Icon>
  );
}

/** サーバー側。ラックに積まれた 2 台。 */
export function IconServer({ size }: IconProps) {
  return (
    <Icon size={size}>
      <rect x="3" y="4" width="18" height="7" rx="1.8" />
      <rect x="3" y="13" width="18" height="7" rx="1.8" />
      <path d="M6.5 7.5h.01M6.5 16.5h.01" />
      <path d="M10 7.5h6M10 16.5h6" />
    </Icon>
  );
}

/** 経路をのぞいている第三者。 */
export function IconEye({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M2 12s3.6-6 10-6 10 6 10 6-3.6 6-10 6-10-6-10-6Z" />
      <circle cx="12" cy="12" r="2.6" />
    </Icon>
  );
}

/** 守りが有効な状態。 */
export function IconShield({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M12 3l7.5 2.6v5.6c0 4.3-3 7.7-7.5 9.2-4.5-1.5-7.5-4.9-7.5-9.2V5.6L12 3Z" />
      <path d="M8.8 12.2l2.2 2.2 4.2-4.4" />
    </Icon>
  );
}

/** 守りを外した状態。盾に割れ目が入る。 */
export function IconShieldBroken({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M12 3l7.5 2.6v5.6c0 4.3-3 7.7-7.5 9.2-4.5-1.5-7.5-4.9-7.5-9.2V5.6L12 3Z" />
      <path d="M12.6 4.4l-2 5.4 3 1.4-2.2 5.6" />
    </Icon>
  );
}

/** 封のある通信。 */
export function IconLock({ size }: IconProps) {
  return (
    <Icon size={size}>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="2.2" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
      <path d="M12 14.3v2.4" />
    </Icon>
  );
}

/** 封のない通信。 */
export function IconLockOpen({ size }: IconProps) {
  return (
    <Icon size={size}>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="2.2" />
      <path d="M8 10.5V8a4 4 0 0 1 7.6-1.7" />
      <path d="M12 14.3v2.4" />
    </Icon>
  );
}

/** 経路を渡っていく 1 通（封あり）。 */
export function IconEnvelope({ size }: IconProps) {
  return (
    <Icon size={size}>
      <rect x="2.5" y="5" width="19" height="14" rx="2.2" />
      <path d="M3.5 7l8.5 6 8.5-6" />
    </Icon>
  );
}

/** 手元での計算。 */
export function IconGear({ size }: IconProps) {
  return (
    <Icon size={size}>
      <circle cx="12" cy="12" r="3.1" />
      <path d="M12 2.8v2.4M12 18.8v2.4M4.5 12H2.1M21.9 12h-2.4M6.7 6.7 5 5M19 19l-1.7-1.7M6.7 17.3 5 19M19 5l-1.7 1.7" />
    </Icon>
  );
}

/** 攻撃者。 */
export function IconMask({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M2.6 8.4C5 7.2 8.4 6.6 12 6.6s7 .6 9.4 1.8c-.3 4.6-2 7.4-4.6 7.4-1.8 0-3-1-4.8-1-1.8 0-3 1-4.8 1-2.6 0-4.3-2.8-4.6-7.4Z" />
      <path d="M7.6 10.6h1.6M14.8 10.6h1.6" />
    </Icon>
  );
}

// --- 5 つの層 --------------------------------------------------------------

/** Handshake。差し出された 2 本の手。 */
export function IconHandshake({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M2.5 10.5 6 7l4 3.4M21.5 10.5 18 7l-4 3.4" />
      <path d="M10 10.4l2 1.8 2-1.8" />
      <path d="M6 7v7.5l4.6 3.4a2 2 0 0 0 2.8 0L18 14.5V7" />
    </Icon>
  );
}

/** Certificate。リボン付きの証書。 */
export function IconCertificate({ size }: IconProps) {
  return (
    <Icon size={size}>
      <rect x="3.5" y="3.5" width="17" height="12" rx="2" />
      <path d="M7 7.5h7M7 11h4.5" />
      <circle cx="16.6" cy="15.4" r="3.1" />
      <path d="M14.9 18.1 14.2 22l2.4-1.4L19 22l-.7-3.9" />
    </Icon>
  );
}

/** Key Exchange。鍵。 */
export function IconKey({ size }: IconProps) {
  return (
    <Icon size={size}>
      <circle cx="8" cy="8" r="4.2" />
      <path d="M11 11l8.5 8.5M15.5 15l-2 2 2 2 2-2" />
    </Icon>
  );
}

/** HTTPS。地球。 */
export function IconGlobe({ size }: IconProps) {
  return (
    <Icon size={size}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3.2 9.5h17.6M3.2 14.5h17.6" />
      <path d="M12 3c-2.6 2.4-4 5.5-4 9s1.4 6.6 4 9c2.6-2.4 4-5.5 4-9s-1.4-6.6-4-9Z" />
    </Icon>
  );
}

// --- 操作 ------------------------------------------------------------------

export function IconPlay({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M8 5.4v13.2l10-6.6-10-6.6Z" fill="currentColor" />
    </Icon>
  );
}

export function IconPause({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M9 5v14M15 5v14" strokeWidth={2.4} />
    </Icon>
  );
}

export function IconPrev({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M14.5 6.5 9 12l5.5 5.5" strokeWidth={2.2} />
    </Icon>
  );
}

export function IconNext({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M9.5 6.5 15 12l-5.5 5.5" strokeWidth={2.2} />
    </Icon>
  );
}

export function IconReset({ size }: IconProps) {
  return (
    <Icon size={size}>
      <path d="M4 12a8 8 0 1 0 2.6-5.9" />
      <path d="M4 4.4V10h5.4" />
    </Icon>
  );
}
