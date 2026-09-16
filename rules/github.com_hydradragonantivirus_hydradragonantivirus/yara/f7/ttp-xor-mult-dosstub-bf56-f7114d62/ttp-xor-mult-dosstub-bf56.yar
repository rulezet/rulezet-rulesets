rule TTP_XOR_MULT_DOSStub_bf56 {
  strings:
    $key_bf56 = { eb 3e [2] 9f 26 [2] d8 24 [2] 9f 35 [2] d1 39 [2] dd 33 [2] ca 38 [2] d1 76 [2] ec }

  condition:
    any of them
}