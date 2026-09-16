rule TTP_XOR_MULT_DOSStub_07da {
  strings:
    $key_07da = { 53 b2 [2] 27 aa [2] 60 a8 [2] 27 b9 [2] 69 b5 [2] 65 bf [2] 72 b4 [2] 69 fa [2] 54 }

  condition:
    any of them
}