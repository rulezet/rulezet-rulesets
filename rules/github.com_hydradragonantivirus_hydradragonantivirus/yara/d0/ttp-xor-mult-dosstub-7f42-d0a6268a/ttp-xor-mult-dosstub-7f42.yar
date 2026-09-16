rule TTP_XOR_MULT_DOSStub_7f42 {
  strings:
    $key_7f42 = { 2b 2a [2] 5f 32 [2] 18 30 [2] 5f 21 [2] 11 2d [2] 1d 27 [2] 0a 2c [2] 11 62 [2] 2c }

  condition:
    any of them
}