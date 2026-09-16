rule TTP_XOR_MULT_DOSStub_b996 {
  strings:
    $key_b996 = { ed fe [2] 99 e6 [2] de e4 [2] 99 f5 [2] d7 f9 [2] db f3 [2] cc f8 [2] d7 b6 [2] ea }

  condition:
    any of them
}