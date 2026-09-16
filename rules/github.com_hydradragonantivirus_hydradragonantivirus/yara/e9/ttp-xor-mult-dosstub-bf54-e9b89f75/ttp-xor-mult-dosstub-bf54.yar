rule TTP_XOR_MULT_DOSStub_bf54 {
  strings:
    $key_bf54 = { eb 3c [2] 9f 24 [2] d8 26 [2] 9f 37 [2] d1 3b [2] dd 31 [2] ca 3a [2] d1 74 [2] ec }

  condition:
    any of them
}