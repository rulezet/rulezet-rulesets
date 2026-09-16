rule TTP_XOR_MULT_DOSStub_bff6 {
  strings:
    $key_bff6 = { eb 9e [2] 9f 86 [2] d8 84 [2] 9f 95 [2] d1 99 [2] dd 93 [2] ca 98 [2] d1 d6 [2] ec }

  condition:
    any of them
}