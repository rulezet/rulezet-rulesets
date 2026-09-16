rule TTP_XOR_MULT_DOSStub_6f42 {
  strings:
    $key_6f42 = { 3b 2a [2] 4f 32 [2] 08 30 [2] 4f 21 [2] 01 2d [2] 0d 27 [2] 1a 2c [2] 01 62 [2] 3c }

  condition:
    any of them
}