rule TTP_XOR_MULT_DOSStub_2042 {
  strings:
    $key_2042 = { 74 2a [2] 00 32 [2] 47 30 [2] 00 21 [2] 4e 2d [2] 42 27 [2] 55 2c [2] 4e 62 [2] 73 }

  condition:
    any of them
}