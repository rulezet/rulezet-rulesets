rule TTP_XOR_MULT_DOSStub_f0a6 {
  strings:
    $key_f0a6 = { a4 ce [2] d0 d6 [2] 97 d4 [2] d0 c5 [2] 9e c9 [2] 92 c3 [2] 85 c8 [2] 9e 86 [2] a3 }

  condition:
    any of them
}