rule TTP_XOR_MULT_DOSStub_b983 {
  strings:
    $key_b983 = { ed eb [2] 99 f3 [2] de f1 [2] 99 e0 [2] d7 ec [2] db e6 [2] cc ed [2] d7 a3 [2] ea }

  condition:
    any of them
}