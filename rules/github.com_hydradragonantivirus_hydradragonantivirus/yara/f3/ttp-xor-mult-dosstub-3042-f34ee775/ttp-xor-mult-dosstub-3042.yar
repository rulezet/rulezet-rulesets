rule TTP_XOR_MULT_DOSStub_3042 {
  strings:
    $key_3042 = { 64 2a [2] 10 32 [2] 57 30 [2] 10 21 [2] 5e 2d [2] 52 27 [2] 45 2c [2] 5e 62 [2] 63 }

  condition:
    any of them
}