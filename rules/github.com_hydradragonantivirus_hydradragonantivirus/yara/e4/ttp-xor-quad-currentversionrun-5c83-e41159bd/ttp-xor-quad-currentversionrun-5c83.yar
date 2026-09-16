rule TTP_XOR_QUAD_CurrentVersionRun_5c83 {
  strings:
    $key_5c83 = { 0f ec [2] 2b e2 [2] 00 ce [2] 2e ec [2] 3a f7 [2] 35 ed [2] 2b f0 [2] 29 f1 [2] 32 f7 [2] 2e f0 [2] 32 df }

  condition:
    any of them
}