rule TTP_XOR_QUAD_CurrentVersionRun_4583 {
  strings:
    $key_4583 = { 16 ec [2] 32 e2 [2] 19 ce [2] 37 ec [2] 23 f7 [2] 2c ed [2] 32 f0 [2] 30 f1 [2] 2b f7 [2] 37 f0 [2] 2b df }

  condition:
    any of them
}