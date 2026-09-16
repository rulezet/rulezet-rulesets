rule TTP_XOR_QUAD_CurrentVersionRun_b1b5 {
  strings:
    $key_b1b5 = { e2 da [2] c6 d4 [2] ed f8 [2] c3 da [2] d7 c1 [2] d8 db [2] c6 c6 [2] c4 c7 [2] df c1 [2] c3 c6 [2] df e9 }

  condition:
    any of them
}