rule TTP_XOR_MULT_DOSStub_bf40 {
  strings:
    $key_bf40 = { eb 28 [2] 9f 30 [2] d8 32 [2] 9f 23 [2] d1 2f [2] dd 25 [2] ca 2e [2] d1 60 [2] ec }

  condition:
    any of them
}