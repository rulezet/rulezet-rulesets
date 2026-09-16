rule TTP_XOR_QUAD_CurrentVersionRun_e5b3 {
  strings:
    $key_e5b3 = { b6 dc [2] 92 d2 [2] b9 fe [2] 97 dc [2] 83 c7 [2] 8c dd [2] 92 c0 [2] 90 c1 [2] 8b c7 [2] 97 c0 [2] 8b ef }

  condition:
    any of them
}