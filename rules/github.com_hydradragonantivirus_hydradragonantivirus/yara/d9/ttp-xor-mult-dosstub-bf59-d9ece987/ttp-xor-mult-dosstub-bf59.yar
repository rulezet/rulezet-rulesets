rule TTP_XOR_MULT_DOSStub_bf59 {
  strings:
    $key_bf59 = { eb 31 [2] 9f 29 [2] d8 2b [2] 9f 3a [2] d1 36 [2] dd 3c [2] ca 37 [2] d1 79 [2] ec }

  condition:
    any of them
}