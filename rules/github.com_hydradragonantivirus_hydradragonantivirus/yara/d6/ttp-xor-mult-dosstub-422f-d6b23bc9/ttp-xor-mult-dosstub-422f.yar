rule TTP_XOR_MULT_DOSStub_422f {
  strings:
    $key_422f = { 16 47 [2] 62 5f [2] 25 5d [2] 62 4c [2] 2c 40 [2] 20 4a [2] 37 41 [2] 2c 0f [2] 11 }

  condition:
    any of them
}