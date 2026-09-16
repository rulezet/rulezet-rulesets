rule TTP_XOR_MULT_DOSStub_bf84 {
  strings:
    $key_bf84 = { eb ec [2] 9f f4 [2] d8 f6 [2] 9f e7 [2] d1 eb [2] dd e1 [2] ca ea [2] d1 a4 [2] ec }

  condition:
    any of them
}