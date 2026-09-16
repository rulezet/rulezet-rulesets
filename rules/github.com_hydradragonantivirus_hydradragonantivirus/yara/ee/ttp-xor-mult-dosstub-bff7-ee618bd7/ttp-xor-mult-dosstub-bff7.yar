rule TTP_XOR_MULT_DOSStub_bff7 {
  strings:
    $key_bff7 = { eb 9f [2] 9f 87 [2] d8 85 [2] 9f 94 [2] d1 98 [2] dd 92 [2] ca 99 [2] d1 d7 [2] ec }

  condition:
    any of them
}