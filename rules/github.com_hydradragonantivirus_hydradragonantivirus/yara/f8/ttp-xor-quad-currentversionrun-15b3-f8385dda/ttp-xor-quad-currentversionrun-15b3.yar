rule TTP_XOR_QUAD_CurrentVersionRun_15b3 {
  strings:
    $key_15b3 = { 46 dc [2] 62 d2 [2] 49 fe [2] 67 dc [2] 73 c7 [2] 7c dd [2] 62 c0 [2] 60 c1 [2] 7b c7 [2] 67 c0 [2] 7b ef }

  condition:
    any of them
}