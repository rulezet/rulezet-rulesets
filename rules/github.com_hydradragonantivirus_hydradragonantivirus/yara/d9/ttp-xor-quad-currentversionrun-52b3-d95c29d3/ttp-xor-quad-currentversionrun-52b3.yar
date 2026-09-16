rule TTP_XOR_QUAD_CurrentVersionRun_52b3 {
  strings:
    $key_52b3 = { 01 dc [2] 25 d2 [2] 0e fe [2] 20 dc [2] 34 c7 [2] 3b dd [2] 25 c0 [2] 27 c1 [2] 3c c7 [2] 20 c0 [2] 3c ef }

  condition:
    any of them
}