rule TTP_XOR_QUAD_CurrentVersionRun_65b3 {
  strings:
    $key_65b3 = { 36 dc [2] 12 d2 [2] 39 fe [2] 17 dc [2] 03 c7 [2] 0c dd [2] 12 c0 [2] 10 c1 [2] 0b c7 [2] 17 c0 [2] 0b ef }

  condition:
    any of them
}