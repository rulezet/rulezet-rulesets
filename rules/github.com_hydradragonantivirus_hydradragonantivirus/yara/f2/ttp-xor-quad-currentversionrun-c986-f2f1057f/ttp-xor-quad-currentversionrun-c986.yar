rule TTP_XOR_QUAD_CurrentVersionRun_c986 {
  strings:
    $key_c986 = { 9a e9 [2] be e7 [2] 95 cb [2] bb e9 [2] af f2 [2] a0 e8 [2] be f5 [2] bc f4 [2] a7 f2 [2] bb f5 [2] a7 da }

  condition:
    any of them
}