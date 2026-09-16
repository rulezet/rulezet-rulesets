rule TTP_XOR_MULT_DOSStub_96da {
  strings:
    $key_96da = { c2 b2 [2] b6 aa [2] f1 a8 [2] b6 b9 [2] f8 b5 [2] f4 bf [2] e3 b4 [2] f8 fa [2] c5 }

  condition:
    any of them
}