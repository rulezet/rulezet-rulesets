rule TTP_XOR_QUAD_CurrentVersionRun_2491 {
  strings:
    $key_2491 = { 77 fe [2] 53 f0 [2] 78 dc [2] 56 fe [2] 42 e5 [2] 4d ff [2] 53 e2 [2] 51 e3 [2] 4a e5 [2] 56 e2 [2] 4a cd }

  condition:
    any of them
}