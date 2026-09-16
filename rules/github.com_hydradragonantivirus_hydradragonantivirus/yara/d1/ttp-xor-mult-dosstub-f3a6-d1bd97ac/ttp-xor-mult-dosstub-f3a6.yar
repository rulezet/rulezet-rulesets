rule TTP_XOR_MULT_DOSStub_f3a6 {
  strings:
    $key_f3a6 = { a7 ce [2] d3 d6 [2] 94 d4 [2] d3 c5 [2] 9d c9 [2] 91 c3 [2] 86 c8 [2] 9d 86 [2] a0 }

  condition:
    any of them
}