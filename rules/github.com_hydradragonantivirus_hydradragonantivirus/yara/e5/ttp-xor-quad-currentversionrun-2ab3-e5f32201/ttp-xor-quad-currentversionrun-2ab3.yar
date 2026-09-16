rule TTP_XOR_QUAD_CurrentVersionRun_2ab3 {
  strings:
    $key_2ab3 = { 79 dc [2] 5d d2 [2] 76 fe [2] 58 dc [2] 4c c7 [2] 43 dd [2] 5d c0 [2] 5f c1 [2] 44 c7 [2] 58 c0 [2] 44 ef }

  condition:
    any of them
}