rule TTP_XOR_MULT_DOSStub_f411 {
  strings:
    $key_f411 = { a0 79 [2] d4 61 [2] 93 63 [2] d4 72 [2] 9a 7e [2] 96 74 [2] 81 7f [2] 9a 31 [2] a7 }

  condition:
    any of them
}