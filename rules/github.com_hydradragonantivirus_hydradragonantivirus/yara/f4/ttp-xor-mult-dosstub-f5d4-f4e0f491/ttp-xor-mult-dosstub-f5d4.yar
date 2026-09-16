rule TTP_XOR_MULT_DOSStub_f5d4 {
  strings:
    $key_f5d4 = { a1 bc [2] d5 a4 [2] 92 a6 [2] d5 b7 [2] 9b bb [2] 97 b1 [2] 80 ba [2] 9b f4 [2] a6 }

  condition:
    any of them
}