rule TTP_XOR_QUAD_CurrentVersionRun_ebb3 {
  strings:
    $key_ebb3 = { b8 dc [2] 9c d2 [2] b7 fe [2] 99 dc [2] 8d c7 [2] 82 dd [2] 9c c0 [2] 9e c1 [2] 85 c7 [2] 99 c0 [2] 85 ef }

  condition:
    any of them
}