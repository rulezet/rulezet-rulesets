rule TTP_XOR_MULT_DOSStub_bf36 {
  strings:
    $key_bf36 = { eb 5e [2] 9f 46 [2] d8 44 [2] 9f 55 [2] d1 59 [2] dd 53 [2] ca 58 [2] d1 16 [2] ec }

  condition:
    any of them
}