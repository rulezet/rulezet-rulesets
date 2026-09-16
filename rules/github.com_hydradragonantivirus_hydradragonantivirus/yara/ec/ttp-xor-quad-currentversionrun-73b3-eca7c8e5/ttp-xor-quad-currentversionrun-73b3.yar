rule TTP_XOR_QUAD_CurrentVersionRun_73b3 {
  strings:
    $key_73b3 = { 20 dc [2] 04 d2 [2] 2f fe [2] 01 dc [2] 15 c7 [2] 1a dd [2] 04 c0 [2] 06 c1 [2] 1d c7 [2] 01 c0 [2] 1d ef }

  condition:
    any of them
}