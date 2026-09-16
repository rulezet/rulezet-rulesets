rule TTP_XOR_MULT_DOSStub_bf79 {
  strings:
    $key_bf79 = { eb 11 [2] 9f 09 [2] d8 0b [2] 9f 1a [2] d1 16 [2] dd 1c [2] ca 17 [2] d1 59 [2] ec }

  condition:
    any of them
}