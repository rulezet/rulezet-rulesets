rule TTP_XOR_MULT_DOSStub_35da {
  strings:
    $key_35da = { 61 b2 [2] 15 aa [2] 52 a8 [2] 15 b9 [2] 5b b5 [2] 57 bf [2] 40 b4 [2] 5b fa [2] 66 }

  condition:
    any of them
}