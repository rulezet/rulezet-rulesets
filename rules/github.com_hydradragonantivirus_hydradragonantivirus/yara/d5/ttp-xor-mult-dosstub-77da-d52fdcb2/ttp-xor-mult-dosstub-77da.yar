rule TTP_XOR_MULT_DOSStub_77da {
  strings:
    $key_77da = { 23 b2 [2] 57 aa [2] 10 a8 [2] 57 b9 [2] 19 b5 [2] 15 bf [2] 02 b4 [2] 19 fa [2] 24 }

  condition:
    any of them
}