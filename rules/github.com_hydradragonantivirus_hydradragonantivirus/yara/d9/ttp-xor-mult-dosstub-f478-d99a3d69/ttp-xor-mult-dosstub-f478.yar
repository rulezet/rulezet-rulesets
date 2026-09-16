rule TTP_XOR_MULT_DOSStub_f478 {
  strings:
    $key_f478 = { a0 10 [2] d4 08 [2] 93 0a [2] d4 1b [2] 9a 17 [2] 96 1d [2] 81 16 [2] 9a 58 [2] a7 }

  condition:
    any of them
}