rule TTP_XOR_QUAD_CurrentVersionRun_1483 {
  strings:
    $key_1483 = { 47 ec [2] 63 e2 [2] 48 ce [2] 66 ec [2] 72 f7 [2] 7d ed [2] 63 f0 [2] 61 f1 [2] 7a f7 [2] 66 f0 [2] 7a df }

  condition:
    any of them
}