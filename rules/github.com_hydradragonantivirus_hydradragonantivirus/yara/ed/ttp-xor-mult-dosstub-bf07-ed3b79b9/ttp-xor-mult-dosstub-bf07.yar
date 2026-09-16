rule TTP_XOR_MULT_DOSStub_bf07 {
  strings:
    $key_bf07 = { eb 6f [2] 9f 77 [2] d8 75 [2] 9f 64 [2] d1 68 [2] dd 62 [2] ca 69 [2] d1 27 [2] ec }

  condition:
    any of them
}