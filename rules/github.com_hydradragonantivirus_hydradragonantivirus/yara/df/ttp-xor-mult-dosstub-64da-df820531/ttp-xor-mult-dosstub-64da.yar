rule TTP_XOR_MULT_DOSStub_64da {
  strings:
    $key_64da = { 30 b2 [2] 44 aa [2] 03 a8 [2] 44 b9 [2] 0a b5 [2] 06 bf [2] 11 b4 [2] 0a fa [2] 37 }

  condition:
    any of them
}