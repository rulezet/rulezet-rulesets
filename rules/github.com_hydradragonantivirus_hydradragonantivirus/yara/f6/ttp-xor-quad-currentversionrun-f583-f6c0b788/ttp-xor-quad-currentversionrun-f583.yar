rule TTP_XOR_QUAD_CurrentVersionRun_f583 {
  strings:
    $key_f583 = { a6 ec [2] 82 e2 [2] a9 ce [2] 87 ec [2] 93 f7 [2] 9c ed [2] 82 f0 [2] 80 f1 [2] 9b f7 [2] 87 f0 [2] 9b df }

  condition:
    any of them
}