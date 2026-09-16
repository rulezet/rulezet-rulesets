rule TTP_XOR_MULT_DOSStub_85da {
  strings:
    $key_85da = { d1 b2 [2] a5 aa [2] e2 a8 [2] a5 b9 [2] eb b5 [2] e7 bf [2] f0 b4 [2] eb fa [2] d6 }

  condition:
    any of them
}