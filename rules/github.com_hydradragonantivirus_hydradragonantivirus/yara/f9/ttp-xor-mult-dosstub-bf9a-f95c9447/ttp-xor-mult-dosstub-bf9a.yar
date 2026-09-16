rule TTP_XOR_MULT_DOSStub_bf9a {
  strings:
    $key_bf9a = { eb f2 [2] 9f ea [2] d8 e8 [2] 9f f9 [2] d1 f5 [2] dd ff [2] ca f4 [2] d1 ba [2] ec }

  condition:
    any of them
}