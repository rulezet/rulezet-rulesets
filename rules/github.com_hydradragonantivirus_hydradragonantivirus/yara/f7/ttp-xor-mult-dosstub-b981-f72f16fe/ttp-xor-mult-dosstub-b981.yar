rule TTP_XOR_MULT_DOSStub_b981 {
  strings:
    $key_b981 = { ed e9 [2] 99 f1 [2] de f3 [2] 99 e2 [2] d7 ee [2] db e4 [2] cc ef [2] d7 a1 [2] ea }

  condition:
    any of them
}