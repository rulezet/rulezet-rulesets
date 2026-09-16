rule TTP_XOR_QUAD_CurrentVersionRun_46b3 {
  strings:
    $key_46b3 = { 15 dc [2] 31 d2 [2] 1a fe [2] 34 dc [2] 20 c7 [2] 2f dd [2] 31 c0 [2] 33 c1 [2] 28 c7 [2] 34 c0 [2] 28 ef }

  condition:
    any of them
}