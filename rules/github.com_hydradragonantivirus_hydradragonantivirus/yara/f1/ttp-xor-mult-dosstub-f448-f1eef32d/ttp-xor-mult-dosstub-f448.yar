rule TTP_XOR_MULT_DOSStub_f448 {
  strings:
    $key_f448 = { a0 20 [2] d4 38 [2] 93 3a [2] d4 2b [2] 9a 27 [2] 96 2d [2] 81 26 [2] 9a 68 [2] a7 }

  condition:
    any of them
}