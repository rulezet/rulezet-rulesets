rule TTP_XOR_QUAD_CurrentVersionRun_57b6 {
  strings:
    $key_57b6 = { 04 d9 [2] 20 d7 [2] 0b fb [2] 25 d9 [2] 31 c2 [2] 3e d8 [2] 20 c5 [2] 22 c4 [2] 39 c2 [2] 25 c5 [2] 39 ea }

  condition:
    any of them
}