rule TTP_XOR_QUAD_CurrentVersionRun_6083 {
  strings:
    $key_6083 = { 33 ec [2] 17 e2 [2] 3c ce [2] 12 ec [2] 06 f7 [2] 09 ed [2] 17 f0 [2] 15 f1 [2] 0e f7 [2] 12 f0 [2] 0e df }

  condition:
    any of them
}