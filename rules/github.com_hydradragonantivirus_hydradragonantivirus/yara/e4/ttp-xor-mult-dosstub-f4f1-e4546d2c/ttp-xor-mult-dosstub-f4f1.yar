rule TTP_XOR_MULT_DOSStub_f4f1 {
  strings:
    $key_f4f1 = { a0 99 [2] d4 81 [2] 93 83 [2] d4 92 [2] 9a 9e [2] 96 94 [2] 81 9f [2] 9a d1 [2] a7 }

  condition:
    any of them
}