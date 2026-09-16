rule TTP_XOR_MULT_DOSStub_2a42 {
  strings:
    $key_2a42 = { 7e 2a [2] 0a 32 [2] 4d 30 [2] 0a 21 [2] 44 2d [2] 48 27 [2] 5f 2c [2] 44 62 [2] 79 }

  condition:
    any of them
}