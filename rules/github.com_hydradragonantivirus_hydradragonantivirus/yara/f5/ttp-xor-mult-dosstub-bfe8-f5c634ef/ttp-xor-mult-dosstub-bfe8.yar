rule TTP_XOR_MULT_DOSStub_bfe8 {
  strings:
    $key_bfe8 = { eb 80 [2] 9f 98 [2] d8 9a [2] 9f 8b [2] d1 87 [2] dd 8d [2] ca 86 [2] d1 c8 [2] ec }

  condition:
    any of them
}