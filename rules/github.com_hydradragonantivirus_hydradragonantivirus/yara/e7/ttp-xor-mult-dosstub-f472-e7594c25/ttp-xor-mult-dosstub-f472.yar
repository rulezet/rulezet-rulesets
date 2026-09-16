rule TTP_XOR_MULT_DOSStub_f472 {
  strings:
    $key_f472 = { a0 1a [2] d4 02 [2] 93 00 [2] d4 11 [2] 9a 1d [2] 96 17 [2] 81 1c [2] 9a 52 [2] a7 }

  condition:
    any of them
}