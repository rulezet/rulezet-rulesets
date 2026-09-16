rule TTP_XOR_QUAD_CurrentVersionRun_60b6 {
  strings:
    $key_60b6 = { 33 d9 [2] 17 d7 [2] 3c fb [2] 12 d9 [2] 06 c2 [2] 09 d8 [2] 17 c5 [2] 15 c4 [2] 0e c2 [2] 12 c5 [2] 0e ea }

  condition:
    any of them
}