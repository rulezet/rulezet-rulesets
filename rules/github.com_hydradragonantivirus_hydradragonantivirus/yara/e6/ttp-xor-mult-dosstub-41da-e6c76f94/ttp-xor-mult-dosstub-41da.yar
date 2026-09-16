rule TTP_XOR_MULT_DOSStub_41da {
  strings:
    $key_41da = { 15 b2 [2] 61 aa [2] 26 a8 [2] 61 b9 [2] 2f b5 [2] 23 bf [2] 34 b4 [2] 2f fa [2] 12 }

  condition:
    any of them
}