rule TTP_XOR_MULT_DOSStub_f6c6 {
  strings:
    $key_f6c6 = { a2 ae [2] d6 b6 [2] 91 b4 [2] d6 a5 [2] 98 a9 [2] 94 a3 [2] 83 a8 [2] 98 e6 [2] a5 }

  condition:
    any of them
}