# mlkem

## ML-KEM vs Diffe-Hellman/Curve25519 
従来の鍵交換 (Diffie-Hellman / Curve25519):
  A: 秘密鍵a → 公開鍵A    B: 秘密鍵b → 公開鍵B
  A: shared = a * B        B: shared = b * A
  → 量子コンピュータで a, b が計算できてしまう

ML-KEM (格子暗号ベース):
  B: 鍵ペア生成 → (秘密鍵dk, 公開鍵ek)
  A: ek でカプセル化 → (共有秘密, 暗号文ct)
  B: dk + ct でデカプセル化 → 共有秘密
  → 量子コンピュータでも格子問題は解けない

presharedKeyでPQC対応はしている。[5.2](https://www.wireguard.com/papers/wireguard.pdf)

- crypto/mlkem	Go 1.24+	ML-KEM-768 カプセル化/デカプセル化
- crypto/mldsa	Go 1.27 (proposal golang/go#77626)	CSAC Phase 2 でのハイブリッド署名（future?）
