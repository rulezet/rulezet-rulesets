rule TTP_XOR_MULT_DOSStub_14da {
  strings:
    $key_14da = { 40 b2 [2] 34 aa [2] 73 a8 [2] 34 b9 [2] 7a b5 [2] 76 bf [2] 61 b4 [2] 7a fa [2] 47 }

  condition:
    any of them
}