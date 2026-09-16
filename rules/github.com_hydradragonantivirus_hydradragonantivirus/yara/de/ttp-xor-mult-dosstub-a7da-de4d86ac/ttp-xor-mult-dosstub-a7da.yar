rule TTP_XOR_MULT_DOSStub_a7da {
  strings:
    $key_a7da = { f3 b2 [2] 87 aa [2] c0 a8 [2] 87 b9 [2] c9 b5 [2] c5 bf [2] d2 b4 [2] c9 fa [2] f4 }

  condition:
    any of them
}