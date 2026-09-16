rule TTP_XOR_QUAD_CurrentVersionRun_7f83 {
  strings:
    $key_7f83 = { 2c ec [2] 08 e2 [2] 23 ce [2] 0d ec [2] 19 f7 [2] 16 ed [2] 08 f0 [2] 0a f1 [2] 11 f7 [2] 0d f0 [2] 11 df }

  condition:
    any of them
}