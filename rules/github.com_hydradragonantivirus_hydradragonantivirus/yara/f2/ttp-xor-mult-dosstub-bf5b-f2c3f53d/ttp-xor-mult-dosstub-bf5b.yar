rule TTP_XOR_MULT_DOSStub_bf5b {
  strings:
    $key_bf5b = { eb 33 [2] 9f 2b [2] d8 29 [2] 9f 38 [2] d1 34 [2] dd 3e [2] ca 35 [2] d1 7b [2] ec }

  condition:
    any of them
}