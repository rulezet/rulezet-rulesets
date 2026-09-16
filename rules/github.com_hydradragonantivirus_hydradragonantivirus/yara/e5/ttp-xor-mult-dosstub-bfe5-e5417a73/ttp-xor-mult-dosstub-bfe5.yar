rule TTP_XOR_MULT_DOSStub_bfe5 {
  strings:
    $key_bfe5 = { eb 8d [2] 9f 95 [2] d8 97 [2] 9f 86 [2] d1 8a [2] dd 80 [2] ca 8b [2] d1 c5 [2] ec }

  condition:
    any of them
}