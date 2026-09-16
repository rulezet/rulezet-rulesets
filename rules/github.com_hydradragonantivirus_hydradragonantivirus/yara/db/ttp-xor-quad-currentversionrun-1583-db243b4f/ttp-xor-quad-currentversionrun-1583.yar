rule TTP_XOR_QUAD_CurrentVersionRun_1583 {
  strings:
    $key_1583 = { 46 ec [2] 62 e2 [2] 49 ce [2] 67 ec [2] 73 f7 [2] 7c ed [2] 62 f0 [2] 60 f1 [2] 7b f7 [2] 67 f0 [2] 7b df }

  condition:
    any of them
}