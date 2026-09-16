rule TTP_XOR_QUAD_CurrentVersionRun_e797 {
  strings:
    $key_e797 = { b4 f8 [2] 90 f6 [2] bb da [2] 95 f8 [2] 81 e3 [2] 8e f9 [2] 90 e4 [2] 92 e5 [2] 89 e3 [2] 95 e4 [2] 89 cb }

  condition:
    any of them
}