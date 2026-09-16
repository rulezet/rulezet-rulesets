rule TTP_XOR_QUAD_CurrentVersionRun_a796 {
  strings:
    $key_a796 = { f4 f9 [2] d0 f7 [2] fb db [2] d5 f9 [2] c1 e2 [2] ce f8 [2] d0 e5 [2] d2 e4 [2] c9 e2 [2] d5 e5 [2] c9 ca }

  condition:
    any of them
}