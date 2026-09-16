rule TTP_XOR_MULT_DOSStub_27da {
  strings:
    $key_27da = { 73 b2 [2] 07 aa [2] 40 a8 [2] 07 b9 [2] 49 b5 [2] 45 bf [2] 52 b4 [2] 49 fa [2] 74 }

  condition:
    any of them
}