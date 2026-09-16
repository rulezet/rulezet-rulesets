rule TTP_XOR_QUAD_CurrentVersionRun_e491 {
  strings:
    $key_e491 = { b7 fe [2] 93 f0 [2] b8 dc [2] 96 fe [2] 82 e5 [2] 8d ff [2] 93 e2 [2] 91 e3 [2] 8a e5 [2] 96 e2 [2] 8a cd }

  condition:
    any of them
}