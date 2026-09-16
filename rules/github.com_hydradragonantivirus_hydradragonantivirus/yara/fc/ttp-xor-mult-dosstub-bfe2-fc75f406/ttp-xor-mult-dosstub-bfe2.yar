rule TTP_XOR_MULT_DOSStub_bfe2 {
  strings:
    $key_bfe2 = { eb 8a [2] 9f 92 [2] d8 90 [2] 9f 81 [2] d1 8d [2] dd 87 [2] ca 8c [2] d1 c2 [2] ec }

  condition:
    any of them
}