rule TTP_XOR_MULT_DOSStub_56da {
  strings:
    $key_56da = { 02 b2 [2] 76 aa [2] 31 a8 [2] 76 b9 [2] 38 b5 [2] 34 bf [2] 23 b4 [2] 38 fa [2] 05 }

  condition:
    any of them
}