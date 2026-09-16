rule TTP_XOR_MULT_DOSStub_ab86 {
  strings:
    $key_ab86 = { ff ee [2] 8b f6 [2] cc f4 [2] 8b e5 [2] c5 e9 [2] c9 e3 [2] de e8 [2] c5 a6 [2] f8 }

  condition:
    any of them
}