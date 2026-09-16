rule TTP_XOR_QUAD_CurrentVersionRun_75b5 {
  strings:
    $key_75b5 = { 26 da [2] 02 d4 [2] 29 f8 [2] 07 da [2] 13 c1 [2] 1c db [2] 02 c6 [2] 00 c7 [2] 1b c1 [2] 07 c6 [2] 1b e9 }

  condition:
    any of them
}