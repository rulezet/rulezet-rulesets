rule TTP_XOR_MULT_DOSStub_1742 {
  strings:
    $key_1742 = { 43 2a [2] 37 32 [2] 70 30 [2] 37 21 [2] 79 2d [2] 75 27 [2] 62 2c [2] 79 62 [2] 44 }

  condition:
    any of them
}