/**
 * @vitest-environment jsdom
 *
 * 画面が最後まで描画されることの確認。
 *
 * 鍵生成 → ハンドシェイク → 全攻撃の実行までを実際に走らせるため、
 * ロジックとレンダリングを繋いだ状態での動作確認も兼ねている。
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "../src/App";

// jsdom には Web Crypto が入っていないので、Node のものをそのまま使う。
if (!globalThis.crypto?.subtle) {
  const { webcrypto } = await import("node:crypto");
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

const TIMEOUT = { timeout: 15_000 };

afterEach(() => {
  document.body.innerHTML = "";
});

describe("画面の描画", () => {
  it("TLS のツリーと 5 つの層を表示する", async () => {
    render(<App />);
    for (const label of ["Handshake", "Certificate", "Key Exchange", "Encryption", "HTTPS"]) {
      expect(await screen.findAllByText(new RegExp(label), undefined, TIMEOUT)).not.toHaveLength(0);
    }
  });

  it("鍵生成が終わると防御トグルと攻撃マトリクスが出る", async () => {
    render(<App />);
    expect(await screen.findByText("防御トグル", undefined, TIMEOUT)).toBeDefined();
    await waitFor(() => expect(screen.getByText("攻撃マトリクス")).toBeDefined(), TIMEOUT);
  });

  it("初期状態では接続が確立し、すべての攻撃が阻止される", async () => {
    render(<App />);

    const flow = await screen.findByText("正常フローの段階可視化", undefined, TIMEOUT);
    const flowPanel = flow.closest("section");
    if (!flowPanel) throw new Error("フローのパネルが見つからない");
    await waitFor(() => expect(within(flowPanel).getByText("接続確立")).toBeDefined(), TIMEOUT);

    const attacks = screen.getByText("攻撃マトリクス");
    const attackPanel = attacks.closest("section");
    if (!attackPanel) throw new Error("攻撃のパネルが見つからない");
    await waitFor(() => expect(within(attackPanel).getByText("すべて阻止")).toBeDefined(), TIMEOUT);
    expect(within(attackPanel).queryByText("攻撃成立")).toBeNull();
  });

  it("ハンドシェイクの各ステップが番号付きで並ぶ", async () => {
    render(<App />);
    expect(await screen.findByText(/① ClientHello/, undefined, TIMEOUT)).toBeDefined();
    expect(screen.getByText(/② ServerHello/)).toBeDefined();
    expect(screen.getByText(/⑬ HTTP レスポンスを受け取る/)).toBeDefined();
  });

  it("盗聴者ビューでアプリデータが暗号文として表示される", async () => {
    render(<App />);
    const wiretap = await screen.findByText("経路上の盗聴者に見えているもの", undefined, TIMEOUT);
    const panel = wiretap.closest("section");
    if (!panel) throw new Error("盗聴者のパネルが見つからない");
    expect(within(panel).getByText("アプリデータは暗号文のみ")).toBeDefined();
    // SNI だけは暗号化しても平文で漏れる。
    expect(within(panel).getByText(/SNI: bank\.example\.com/)).toBeDefined();
  });
});

describe("防御トグルの操作", () => {
  /**
   * ラベル名からトグルのチェックボックスを引く。
   * 同じ防御名は攻撃マトリクスにも出るので、防御パネル内に限定して探す。
   */
  async function toggle(label: string) {
    const panel = (await screen.findByText("防御トグル", undefined, TIMEOUT)).closest("section");
    if (!panel) throw new Error("防御トグルのパネルが見つからない");
    const labelEl = within(panel).getByText(label).closest("label");
    if (!labelEl) throw new Error(`トグル "${label}" が見つからない`);
    return within(labelEl).getByRole("checkbox");
  }

  it("チェーン検証を OFF にすると中間者攻撃が成立する", async () => {
    render(<App />);
    const attackPanel = (await screen.findByText("攻撃マトリクス", undefined, TIMEOUT)).closest(
      "section",
    );
    if (!attackPanel) throw new Error("攻撃のパネルが見つからない");
    await waitFor(() => expect(within(attackPanel).getByText("すべて阻止")).toBeDefined(), TIMEOUT);

    fireEvent.click(await toggle("証明書チェーン検証"));

    const mitm = within(attackPanel).getByText("中間者攻撃（偽 CA の証明書）").closest("li");
    if (!mitm) throw new Error("中間者攻撃の行が見つからない");
    await waitFor(() => expect(within(mitm).getByText("攻撃成立")).toBeDefined(), TIMEOUT);

    // 攻撃者が実際に平文を手にしていることまで表示される。
    expect(within(mitm).getByText(/Authorization: Bearer/)).toBeDefined();
  });

  it("他の攻撃は影響を受けない（防御と攻撃が 1 対 1）", async () => {
    render(<App />);
    const attackPanel = (await screen.findByText("攻撃マトリクス", undefined, TIMEOUT)).closest(
      "section",
    );
    if (!attackPanel) throw new Error("攻撃のパネルが見つからない");
    await waitFor(() => expect(within(attackPanel).getByText("すべて阻止")).toBeDefined(), TIMEOUT);

    fireEvent.click(await toggle("証明書チェーン検証"));
    await waitFor(
      () => expect(within(attackPanel).getAllByText("攻撃成立")).toHaveLength(1),
      TIMEOUT,
    );
  });

  it("レコード暗号化を OFF にすると盗聴で HTTP が読める", async () => {
    render(<App />);
    const wiretapPanel = (
      await screen.findByText("経路上の盗聴者に見えているもの", undefined, TIMEOUT)
    ).closest("section");
    if (!wiretapPanel) throw new Error("盗聴者のパネルが見つからない");

    fireEvent.click(await toggle("レコード層の暗号化（AEAD）"));

    await waitFor(
      () => expect(within(wiretapPanel).getByText(/HTTP 2 件が平文で読める/)).toBeDefined(),
      TIMEOUT,
    );
    expect(within(wiretapPanel).getByText(/Authorization: Bearer/)).toBeDefined();
  });

  it("すべて ON に戻すボタンで初期状態に復帰する", async () => {
    render(<App />);
    const attackPanel = (await screen.findByText("攻撃マトリクス", undefined, TIMEOUT)).closest(
      "section",
    );
    if (!attackPanel) throw new Error("攻撃のパネルが見つからない");
    await waitFor(() => expect(within(attackPanel).getByText("すべて阻止")).toBeDefined(), TIMEOUT);

    fireEvent.click(await toggle("証明書チェーン検証"));
    await waitFor(() => expect(within(attackPanel).getByText("攻撃成立")).toBeDefined(), TIMEOUT);

    fireEvent.click(screen.getByRole("button", { name: "すべて ON に戻す" }));
    await waitFor(() => expect(within(attackPanel).getByText("すべて阻止")).toBeDefined(), TIMEOUT);
  });
});
