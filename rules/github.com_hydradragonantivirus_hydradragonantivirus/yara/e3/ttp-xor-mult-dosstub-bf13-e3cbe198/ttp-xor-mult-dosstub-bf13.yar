rule TTP_XOR_MULT_DOSStub_bf13 {
  strings:
    $key_bf13 = { eb 7b [2] 9f 63 [2] d8 61 [2] 9f 70 [2] d1 7c [2] dd 76 [2] ca 7d [2] d1 33 [2] ec }

  condition:
    any of them
}