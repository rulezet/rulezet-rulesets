rule TTP_XOR_MULT_DOSStub_bf9d {
  strings:
    $key_bf9d = { eb f5 [2] 9f ed [2] d8 ef [2] 9f fe [2] d1 f2 [2] dd f8 [2] ca f3 [2] d1 bd [2] ec }

  condition:
    any of them
}