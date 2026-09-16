rule TTP_XOR_QUAD_CurrentVersionRun_0083 {
  strings:
    $key_0083 = { 53 ec [2] 77 e2 [2] 5c ce [2] 72 ec [2] 66 f7 [2] 69 ed [2] 77 f0 [2] 75 f1 [2] 6e f7 [2] 72 f0 [2] 6e df }

  condition:
    any of them
}