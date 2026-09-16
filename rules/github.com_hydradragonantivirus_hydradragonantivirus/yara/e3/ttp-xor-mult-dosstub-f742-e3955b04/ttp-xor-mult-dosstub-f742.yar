rule TTP_XOR_MULT_DOSStub_f742 {
  strings:
    $key_f742 = { a3 2a [2] d7 32 [2] 90 30 [2] d7 21 [2] 99 2d [2] 95 27 [2] 82 2c [2] 99 62 [2] a4 }

  condition:
    any of them
}