rule TTP_XOR_MULT_DOSStub_bf48 {
  strings:
    $key_bf48 = { eb 20 [2] 9f 38 [2] d8 3a [2] 9f 2b [2] d1 27 [2] dd 2d [2] ca 26 [2] d1 68 [2] ec }

  condition:
    any of them
}