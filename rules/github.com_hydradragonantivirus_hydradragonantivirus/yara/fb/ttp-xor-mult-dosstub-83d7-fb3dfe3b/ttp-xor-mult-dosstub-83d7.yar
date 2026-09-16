rule TTP_XOR_MULT_DOSStub_83d7 {
  strings:
    $key_83d7 = { d7 bf [2] a3 a7 [2] e4 a5 [2] a3 b4 [2] ed b8 [2] e1 b2 [2] f6 b9 [2] ed f7 [2] d0 }

  condition:
    any of them
}