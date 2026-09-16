rule TTP_XOR_QUAD_CurrentVersionRun_37b6 {
  strings:
    $key_37b6 = { 64 d9 [2] 40 d7 [2] 6b fb [2] 45 d9 [2] 51 c2 [2] 5e d8 [2] 40 c5 [2] 42 c4 [2] 59 c2 [2] 45 c5 [2] 59 ea }

  condition:
    any of them
}