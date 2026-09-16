rule TTP_XOR_MULT_DOSStub_bffb {
  strings:
    $key_bffb = { eb 93 [2] 9f 8b [2] d8 89 [2] 9f 98 [2] d1 94 [2] dd 9e [2] ca 95 [2] d1 db [2] ec }

  condition:
    any of them
}