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

