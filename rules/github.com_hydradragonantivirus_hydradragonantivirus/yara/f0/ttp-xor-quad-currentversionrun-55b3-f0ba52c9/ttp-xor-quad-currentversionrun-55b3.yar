rule TTP_XOR_QUAD_CurrentVersionRun_55b3 {
  strings:
    $key_55b3 = { 06 dc [2] 22 d2 [2] 09 fe [2] 27 dc [2] 33 c7 [2] 3c dd [2] 22 c0 [2] 20 c1 [2] 3b c7 [2] 27 c0 [2] 3b ef }

  condition:
    any of them
}