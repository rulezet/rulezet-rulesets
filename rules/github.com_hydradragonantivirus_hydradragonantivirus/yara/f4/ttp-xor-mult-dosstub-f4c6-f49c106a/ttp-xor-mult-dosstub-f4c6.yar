rule TTP_XOR_MULT_DOSStub_f4c6 {
  strings:
    $key_f4c6 = { a0 ae [2] d4 b6 [2] 93 b4 [2] d4 a5 [2] 9a a9 [2] 96 a3 [2] 81 a8 [2] 9a e6 [2] a7 }

  condition:
    any of them
}