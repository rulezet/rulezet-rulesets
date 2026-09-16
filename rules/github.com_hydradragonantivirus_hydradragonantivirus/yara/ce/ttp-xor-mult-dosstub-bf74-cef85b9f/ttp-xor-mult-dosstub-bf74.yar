rule TTP_XOR_MULT_DOSStub_bf74 {
  strings:
    $key_bf74 = { eb 1c [2] 9f 04 [2] d8 06 [2] 9f 17 [2] d1 1b [2] dd 11 [2] ca 1a [2] d1 54 [2] ec }

  condition:
    any of them
}