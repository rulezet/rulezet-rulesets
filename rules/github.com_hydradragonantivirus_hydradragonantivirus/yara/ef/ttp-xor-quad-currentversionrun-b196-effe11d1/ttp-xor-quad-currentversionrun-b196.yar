rule TTP_XOR_QUAD_CurrentVersionRun_b196 {
  strings:
    $key_b196 = { e2 f9 [2] c6 f7 [2] ed db [2] c3 f9 [2] d7 e2 [2] d8 f8 [2] c6 e5 [2] c4 e4 [2] df e2 [2] c3 e5 [2] df ca }

  condition:
    any of them
}