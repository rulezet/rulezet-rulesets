rule TTP_XOR_QUAD_CurrentVersionRun_6686 {
  strings:
    $key_6686 = { 35 e9 [2] 11 e7 [2] 3a cb [2] 14 e9 [2] 00 f2 [2] 0f e8 [2] 11 f5 [2] 13 f4 [2] 08 f2 [2] 14 f5 [2] 08 da }

  condition:
    any of them
}