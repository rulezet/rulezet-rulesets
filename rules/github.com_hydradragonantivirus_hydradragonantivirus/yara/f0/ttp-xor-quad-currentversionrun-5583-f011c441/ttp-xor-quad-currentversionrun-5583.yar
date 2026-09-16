rule TTP_XOR_QUAD_CurrentVersionRun_5583 {
  strings:
    $key_5583 = { 06 ec [2] 22 e2 [2] 09 ce [2] 27 ec [2] 33 f7 [2] 3c ed [2] 22 f0 [2] 20 f1 [2] 3b f7 [2] 27 f0 [2] 3b df }

  condition:
    any of them
}