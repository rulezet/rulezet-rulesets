rule TTP_XOR_QUAD_CurrentVersionRun_a7d5 {
  strings:
    $key_a7d5 = { f4 ba [2] d0 b4 [2] fb 98 [2] d5 ba [2] c1 a1 [2] ce bb [2] d0 a6 [2] d2 a7 [2] c9 a1 [2] d5 a6 [2] c9 89 }

  condition:
    any of them
}