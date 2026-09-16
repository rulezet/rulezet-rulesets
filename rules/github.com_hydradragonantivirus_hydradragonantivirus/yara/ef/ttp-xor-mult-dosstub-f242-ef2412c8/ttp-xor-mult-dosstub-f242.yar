rule TTP_XOR_MULT_DOSStub_f242 {
  strings:
    $key_f242 = { a6 2a [2] d2 32 [2] 95 30 [2] d2 21 [2] 9c 2d [2] 90 27 [2] 87 2c [2] 9c 62 [2] a1 }

  condition:
    any of them
}