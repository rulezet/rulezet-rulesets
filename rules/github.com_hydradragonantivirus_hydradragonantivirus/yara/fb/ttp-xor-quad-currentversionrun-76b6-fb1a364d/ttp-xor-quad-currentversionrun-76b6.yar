rule TTP_XOR_QUAD_CurrentVersionRun_76b6 {
  strings:
    $key_76b6 = { 25 d9 [2] 01 d7 [2] 2a fb [2] 04 d9 [2] 10 c2 [2] 1f d8 [2] 01 c5 [2] 03 c4 [2] 18 c2 [2] 04 c5 [2] 18 ea }

  condition:
    any of them
}