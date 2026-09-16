rule TTP_XOR_MULT_DOSStub_83da {
  strings:
    $key_83da = { d7 b2 [2] a3 aa [2] e4 a8 [2] a3 b9 [2] ed b5 [2] e1 bf [2] f6 b4 [2] ed fa [2] d0 }

  condition:
    any of them
}