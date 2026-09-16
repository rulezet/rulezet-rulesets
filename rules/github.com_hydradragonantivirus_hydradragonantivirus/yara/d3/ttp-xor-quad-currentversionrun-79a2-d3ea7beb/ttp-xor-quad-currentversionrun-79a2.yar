rule TTP_XOR_QUAD_CurrentVersionRun_79a2 {
  strings:
    $key_79a2 = { 2a cd [2] 0e c3 [2] 25 ef [2] 0b cd [2] 1f d6 [2] 10 cc [2] 0e d1 [2] 0c d0 [2] 17 d6 [2] 0b d1 [2] 17 fe }

  condition:
    any of them
}