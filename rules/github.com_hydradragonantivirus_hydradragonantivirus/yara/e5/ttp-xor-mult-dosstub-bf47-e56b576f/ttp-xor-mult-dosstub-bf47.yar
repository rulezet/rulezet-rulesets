rule TTP_XOR_MULT_DOSStub_bf47 {
  strings:
    $key_bf47 = { eb 2f [2] 9f 37 [2] d8 35 [2] 9f 24 [2] d1 28 [2] dd 22 [2] ca 29 [2] d1 67 [2] ec }

  condition:
    any of them
}