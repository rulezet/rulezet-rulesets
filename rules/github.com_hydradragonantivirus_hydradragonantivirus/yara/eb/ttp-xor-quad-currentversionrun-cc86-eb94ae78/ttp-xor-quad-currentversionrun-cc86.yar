rule TTP_XOR_QUAD_CurrentVersionRun_cc86 {
  strings:
    $key_cc86 = { 9f e9 [2] bb e7 [2] 90 cb [2] be e9 [2] aa f2 [2] a5 e8 [2] bb f5 [2] b9 f4 [2] a2 f2 [2] be f5 [2] a2 da }

  condition:
    any of them
}