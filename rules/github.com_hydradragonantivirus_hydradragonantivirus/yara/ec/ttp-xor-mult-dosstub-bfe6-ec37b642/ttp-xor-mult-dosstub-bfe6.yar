rule TTP_XOR_MULT_DOSStub_bfe6 {
  strings:
    $key_bfe6 = { eb 8e [2] 9f 96 [2] d8 94 [2] 9f 85 [2] d1 89 [2] dd 83 [2] ca 88 [2] d1 c6 [2] ec }

  condition:
    any of them
}