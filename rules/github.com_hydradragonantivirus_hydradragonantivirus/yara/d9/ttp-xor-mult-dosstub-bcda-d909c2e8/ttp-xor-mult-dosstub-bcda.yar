rule TTP_XOR_MULT_DOSStub_bcda {
  strings:
    $key_bcda = { e8 b2 [2] 9c aa [2] db a8 [2] 9c b9 [2] d2 b5 [2] de bf [2] c9 b4 [2] d2 fa [2] ef }

  condition:
    any of them
}