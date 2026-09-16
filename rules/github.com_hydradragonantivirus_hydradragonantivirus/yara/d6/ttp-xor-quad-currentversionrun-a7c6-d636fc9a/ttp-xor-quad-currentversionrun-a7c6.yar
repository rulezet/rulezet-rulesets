rule TTP_XOR_QUAD_CurrentVersionRun_a7c6 {
  strings:
    $key_a7c6 = { f4 a9 [2] d0 a7 [2] fb 8b [2] d5 a9 [2] c1 b2 [2] ce a8 [2] d0 b5 [2] d2 b4 [2] c9 b2 [2] d5 b5 [2] c9 9a }

  condition:
    any of them
}