rule TTP_XOR_MULT_DOSStub_bf12 {
  strings:
    $key_bf12 = { eb 7a [2] 9f 62 [2] d8 60 [2] 9f 71 [2] d1 7d [2] dd 77 [2] ca 7c [2] d1 32 [2] ec }

  condition:
    any of them
}