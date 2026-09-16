rule TTP_XOR_MULT_DOSStub_4f42 {
  strings:
    $key_4f42 = { 1b 2a [2] 6f 32 [2] 28 30 [2] 6f 21 [2] 21 2d [2] 2d 27 [2] 3a 2c [2] 21 62 [2] 1c }

  condition:
    any of them
}