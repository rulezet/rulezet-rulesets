rule TTP_XOR_QUAD_CurrentVersionRun_6583 {
  strings:
    $key_6583 = { 36 ec [2] 12 e2 [2] 39 ce [2] 17 ec [2] 03 f7 [2] 0c ed [2] 12 f0 [2] 10 f1 [2] 0b f7 [2] 17 f0 [2] 0b df }

  condition:
    any of them
}