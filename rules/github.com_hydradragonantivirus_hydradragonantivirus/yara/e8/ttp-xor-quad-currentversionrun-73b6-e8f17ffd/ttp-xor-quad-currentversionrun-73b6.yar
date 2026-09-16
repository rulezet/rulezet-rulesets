rule TTP_XOR_QUAD_CurrentVersionRun_73b6 {
  strings:
    $key_73b6 = { 20 d9 [2] 04 d7 [2] 2f fb [2] 01 d9 [2] 15 c2 [2] 1a d8 [2] 04 c5 [2] 06 c4 [2] 1d c2 [2] 01 c5 [2] 1d ea }

  condition:
    any of them
}