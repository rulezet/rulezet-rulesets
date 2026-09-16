rule TTP_XOR_MULT_DOSStub_f444 {
  strings:
    $key_f444 = { a0 2c [2] d4 34 [2] 93 36 [2] d4 27 [2] 9a 2b [2] 96 21 [2] 81 2a [2] 9a 64 [2] a7 }

  condition:
    any of them
}