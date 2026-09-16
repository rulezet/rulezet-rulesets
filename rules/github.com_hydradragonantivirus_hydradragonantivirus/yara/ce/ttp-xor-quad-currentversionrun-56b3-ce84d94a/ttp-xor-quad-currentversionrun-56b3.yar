rule TTP_XOR_QUAD_CurrentVersionRun_56b3 {
  strings:
    $key_56b3 = { 05 dc [2] 21 d2 [2] 0a fe [2] 24 dc [2] 30 c7 [2] 3f dd [2] 21 c0 [2] 23 c1 [2] 38 c7 [2] 24 c0 [2] 38 ef }

  condition:
    any of them
}