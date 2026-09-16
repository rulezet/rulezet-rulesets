rule TTP_XOR_MULT_DOSStub_f087 {
  strings:
    $key_f087 = { a4 ef [2] d0 f7 [2] 97 f5 [2] d0 e4 [2] 9e e8 [2] 92 e2 [2] 85 e9 [2] 9e a7 [2] a3 }

  condition:
    any of them
}