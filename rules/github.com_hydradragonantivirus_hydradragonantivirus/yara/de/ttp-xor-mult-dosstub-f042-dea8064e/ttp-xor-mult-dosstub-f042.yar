rule TTP_XOR_MULT_DOSStub_f042 {
  strings:
    $key_f042 = { a4 2a [2] d0 32 [2] 97 30 [2] d0 21 [2] 9e 2d [2] 92 27 [2] 85 2c [2] 9e 62 [2] a3 }

  condition:
    any of them
}