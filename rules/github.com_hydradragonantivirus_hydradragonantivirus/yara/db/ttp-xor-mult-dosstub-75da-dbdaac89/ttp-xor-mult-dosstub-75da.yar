rule TTP_XOR_MULT_DOSStub_75da {
  strings:
    $key_75da = { 21 b2 [2] 55 aa [2] 12 a8 [2] 55 b9 [2] 1b b5 [2] 17 bf [2] 00 b4 [2] 1b fa [2] 26 }

  condition:
    any of them
}