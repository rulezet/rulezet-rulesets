rule TTP_XOR_MULT_DOSStub_f4f7 {
  strings:
    $key_f4f7 = { a0 9f [2] d4 87 [2] 93 85 [2] d4 94 [2] 9a 98 [2] 96 92 [2] 81 99 [2] 9a d7 [2] a7 }

  condition:
    any of them
}