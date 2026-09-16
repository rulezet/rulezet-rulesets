rule TTP_XOR_QUAD_CurrentVersionRun_0f83 {
  strings:
    $key_0f83 = { 5c ec [2] 78 e2 [2] 53 ce [2] 7d ec [2] 69 f7 [2] 66 ed [2] 78 f0 [2] 7a f1 [2] 61 f7 [2] 7d f0 [2] 61 df }

  condition:
    any of them
}