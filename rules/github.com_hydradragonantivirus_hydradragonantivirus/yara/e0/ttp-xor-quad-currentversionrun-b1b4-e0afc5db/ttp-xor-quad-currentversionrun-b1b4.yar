rule TTP_XOR_QUAD_CurrentVersionRun_b1b4 {
  strings:
    $key_b1b4 = { e2 db [2] c6 d5 [2] ed f9 [2] c3 db [2] d7 c0 [2] d8 da [2] c6 c7 [2] c4 c6 [2] df c0 [2] c3 c7 [2] df e8 }

  condition:
    any of them
}