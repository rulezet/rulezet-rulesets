rule TTP_XOR_QUAD_CurrentVersionRun_b197 {
  strings:
    $key_b197 = { e2 f8 [2] c6 f6 [2] ed da [2] c3 f8 [2] d7 e3 [2] d8 f9 [2] c6 e4 [2] c4 e5 [2] df e3 [2] c3 e4 [2] df cb }

  condition:
    any of them
}