rule TTP_XOR_MULT_DOSStub_feda {
  strings:
    $key_feda = { aa b2 [2] de aa [2] 99 a8 [2] de b9 [2] 90 b5 [2] 9c bf [2] 8b b4 [2] 90 fa [2] ad }

  condition:
    any of them
}