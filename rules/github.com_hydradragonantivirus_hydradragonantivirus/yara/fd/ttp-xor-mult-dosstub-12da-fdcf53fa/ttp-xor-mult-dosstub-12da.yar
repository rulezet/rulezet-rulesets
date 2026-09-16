rule TTP_XOR_MULT_DOSStub_12da {
  strings:
    $key_12da = { 46 b2 [2] 32 aa [2] 75 a8 [2] 32 b9 [2] 7c b5 [2] 70 bf [2] 67 b4 [2] 7c fa [2] 41 }

  condition:
    any of them
}