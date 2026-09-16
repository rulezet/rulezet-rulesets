rule TTP_XOR_QUAD_CurrentVersionRun_d797 {
  strings:
    $key_d797 = { 84 f8 [2] a0 f6 [2] 8b da [2] a5 f8 [2] b1 e3 [2] be f9 [2] a0 e4 [2] a2 e5 [2] b9 e3 [2] a5 e4 [2] b9 cb }

  condition:
    any of them
}