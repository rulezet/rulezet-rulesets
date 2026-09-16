rule TTP_XOR_MULT_DOSStub_4202 {
  strings:
    $key_4202 = { 16 6a [2] 62 72 [2] 25 70 [2] 62 61 [2] 2c 6d [2] 20 67 [2] 37 6c [2] 2c 22 [2] 11 }

  condition:
    any of them
}