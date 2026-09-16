rule TTP_XOR_MULT_DOSStub_f4d9 {
  strings:
    $key_f4d9 = { a0 b1 [2] d4 a9 [2] 93 ab [2] d4 ba [2] 9a b6 [2] 96 bc [2] 81 b7 [2] 9a f9 [2] a7 }

  condition:
    any of them
}