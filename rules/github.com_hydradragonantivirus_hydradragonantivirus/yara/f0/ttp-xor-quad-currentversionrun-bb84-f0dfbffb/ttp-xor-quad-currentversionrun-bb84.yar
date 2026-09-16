rule TTP_XOR_QUAD_CurrentVersionRun_bb84 {
  strings:
    $key_bb84 = { e8 eb [2] cc e5 [2] e7 c9 [2] c9 eb [2] dd f0 [2] d2 ea [2] cc f7 [2] ce f6 [2] d5 f0 [2] c9 f7 [2] d5 d8 }

  condition:
    any of them
}