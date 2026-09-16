rule TTP_XOR_MULT_DOSStub_bf24 {
  strings:
    $key_bf24 = { eb 4c [2] 9f 54 [2] d8 56 [2] 9f 47 [2] d1 4b [2] dd 41 [2] ca 4a [2] d1 04 [2] ec }

  condition:
    any of them
}