rule TTP_XOR_MULT_DOSStub_6cda {
  strings:
    $key_6cda = { 38 b2 [2] 4c aa [2] 0b a8 [2] 4c b9 [2] 02 b5 [2] 0e bf [2] 19 b4 [2] 02 fa [2] 3f }

  condition:
    any of them
}