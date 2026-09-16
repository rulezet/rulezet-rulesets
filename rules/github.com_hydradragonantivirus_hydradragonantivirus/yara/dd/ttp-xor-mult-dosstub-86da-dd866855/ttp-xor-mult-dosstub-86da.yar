rule TTP_XOR_MULT_DOSStub_86da {
  strings:
    $key_86da = { d2 b2 [2] a6 aa [2] e1 a8 [2] a6 b9 [2] e8 b5 [2] e4 bf [2] f3 b4 [2] e8 fa [2] d5 }

  condition:
    any of them
}