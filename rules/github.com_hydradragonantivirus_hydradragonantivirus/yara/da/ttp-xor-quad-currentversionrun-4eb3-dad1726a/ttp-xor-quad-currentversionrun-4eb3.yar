rule TTP_XOR_QUAD_CurrentVersionRun_4eb3 {
  strings:
    $key_4eb3 = { 1d dc [2] 39 d2 [2] 12 fe [2] 3c dc [2] 28 c7 [2] 27 dd [2] 39 c0 [2] 3b c1 [2] 20 c7 [2] 3c c0 [2] 20 ef }

  condition:
    any of them
}