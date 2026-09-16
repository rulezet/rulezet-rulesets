rule TTP_XOR_QUAD_CurrentVersionRun_aa96 {
  strings:
    $key_aa96 = { f9 f9 [2] dd f7 [2] f6 db [2] d8 f9 [2] cc e2 [2] c3 f8 [2] dd e5 [2] df e4 [2] c4 e2 [2] d8 e5 [2] c4 ca }

  condition:
    any of them
}