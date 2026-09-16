rule TTP_XOR_QUAD_CurrentVersionRun_b6b3 {
  strings:
    $key_b6b3 = { e5 dc [2] c1 d2 [2] ea fe [2] c4 dc [2] d0 c7 [2] df dd [2] c1 c0 [2] c3 c1 [2] d8 c7 [2] c4 c0 [2] d8 ef }

  condition:
    any of them
}