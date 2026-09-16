rule TTP_XOR_MULT_DOSStub_f0d4 {
  strings:
    $key_f0d4 = { a4 bc [2] d0 a4 [2] 97 a6 [2] d0 b7 [2] 9e bb [2] 92 b1 [2] 85 ba [2] 9e f4 [2] a3 }

  condition:
    any of them
}