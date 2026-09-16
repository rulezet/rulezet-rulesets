rule TTP_XOR_MULT_DOSStub_bf15 {
  strings:
    $key_bf15 = { eb 7d [2] 9f 65 [2] d8 67 [2] 9f 76 [2] d1 7a [2] dd 70 [2] ca 7b [2] d1 35 [2] ec }

  condition:
    any of them
}