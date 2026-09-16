rule TTP_XOR_MULT_DOSStub_0a42 {
  strings:
    $key_0a42 = { 5e 2a [2] 2a 32 [2] 6d 30 [2] 2a 21 [2] 64 2d [2] 68 27 [2] 7f 2c [2] 64 62 [2] 59 }

  condition:
    any of them
}