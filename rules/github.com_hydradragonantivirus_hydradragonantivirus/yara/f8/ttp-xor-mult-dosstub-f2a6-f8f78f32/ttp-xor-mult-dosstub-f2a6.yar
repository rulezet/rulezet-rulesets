rule TTP_XOR_MULT_DOSStub_f2a6 {
  strings:
    $key_f2a6 = { a6 ce [2] d2 d6 [2] 95 d4 [2] d2 c5 [2] 9c c9 [2] 90 c3 [2] 87 c8 [2] 9c 86 [2] a1 }

  condition:
    any of them
}