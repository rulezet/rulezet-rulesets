rule TTP_XOR_MULT_DOSStub_6542 {
  strings:
    $key_6542 = { 31 2a [2] 45 32 [2] 02 30 [2] 45 21 [2] 0b 2d [2] 07 27 [2] 10 2c [2] 0b 62 [2] 36 }

  condition:
    any of them
}