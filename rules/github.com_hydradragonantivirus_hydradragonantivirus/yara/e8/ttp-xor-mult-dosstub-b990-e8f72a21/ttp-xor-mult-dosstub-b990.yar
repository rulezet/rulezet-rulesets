rule TTP_XOR_MULT_DOSStub_b990 {
  strings:
    $key_b990 = { ed f8 [2] 99 e0 [2] de e2 [2] 99 f3 [2] d7 ff [2] db f5 [2] cc fe [2] d7 b0 [2] ea }

  condition:
    any of them
}