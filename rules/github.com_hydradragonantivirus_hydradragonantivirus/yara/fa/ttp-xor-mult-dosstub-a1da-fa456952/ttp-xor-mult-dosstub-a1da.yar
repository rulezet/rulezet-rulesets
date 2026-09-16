rule TTP_XOR_MULT_DOSStub_a1da {
  strings:
    $key_a1da = { f5 b2 [2] 81 aa [2] c6 a8 [2] 81 b9 [2] cf b5 [2] c3 bf [2] d4 b4 [2] cf fa [2] f2 }

  condition:
    any of them
}