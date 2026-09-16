rule TTP_XOR_MULT_DOSStub_426a {
  strings:
    $key_426a = { 16 02 [2] 62 1a [2] 25 18 [2] 62 09 [2] 2c 05 [2] 20 0f [2] 37 04 [2] 2c 4a [2] 11 }

  condition:
    any of them
}