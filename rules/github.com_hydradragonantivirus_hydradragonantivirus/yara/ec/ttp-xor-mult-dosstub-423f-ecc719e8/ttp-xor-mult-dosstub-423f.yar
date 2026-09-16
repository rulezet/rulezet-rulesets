rule TTP_XOR_MULT_DOSStub_423f {
  strings:
    $key_423f = { 16 57 [2] 62 4f [2] 25 4d [2] 62 5c [2] 2c 50 [2] 20 5a [2] 37 51 [2] 2c 1f [2] 11 }

  condition:
    any of them
}