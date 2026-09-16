rule TTP_XOR_MULT_DOSStub_bf45 {
  strings:
    $key_bf45 = { eb 2d [2] 9f 35 [2] d8 37 [2] 9f 26 [2] d1 2a [2] dd 20 [2] ca 2b [2] d1 65 [2] ec }

  condition:
    any of them
}