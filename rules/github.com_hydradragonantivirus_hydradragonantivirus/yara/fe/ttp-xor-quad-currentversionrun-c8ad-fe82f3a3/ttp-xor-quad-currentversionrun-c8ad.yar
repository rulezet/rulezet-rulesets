rule TTP_XOR_QUAD_CurrentVersionRun_c8ad {
  strings:
    $key_c8ad = { 9b c2 [2] bf cc [2] 94 e0 [2] ba c2 [2] ae d9 [2] a1 c3 [2] bf de [2] bd df [2] a6 d9 [2] ba de [2] a6 f1 }

  condition:
    any of them
}