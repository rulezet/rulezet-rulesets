rule TTP_XOR_QUAD_CurrentVersionRun_6797 {
  strings:
    $key_6797 = { 34 f8 [2] 10 f6 [2] 3b da [2] 15 f8 [2] 01 e3 [2] 0e f9 [2] 10 e4 [2] 12 e5 [2] 09 e3 [2] 15 e4 [2] 09 cb }

  condition:
    any of them
}