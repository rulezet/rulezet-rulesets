rule TTP_XOR_MULT_DOSStub_f476 {
  strings:
    $key_f476 = { a0 1e [2] d4 06 [2] 93 04 [2] d4 15 [2] 9a 19 [2] 96 13 [2] 81 18 [2] 9a 56 [2] a7 }

  condition:
    any of them
}