rule TTP_XOR_MULT_DOSStub_ab84 {
  strings:
    $key_ab84 = { ff ec [2] 8b f4 [2] cc f6 [2] 8b e7 [2] c5 eb [2] c9 e1 [2] de ea [2] c5 a4 [2] f8 }

  condition:
    any of them
}