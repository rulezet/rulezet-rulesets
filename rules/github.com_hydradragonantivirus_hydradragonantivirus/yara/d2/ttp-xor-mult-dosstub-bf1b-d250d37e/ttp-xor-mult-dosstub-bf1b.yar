rule TTP_XOR_MULT_DOSStub_bf1b {
  strings:
    $key_bf1b = { eb 73 [2] 9f 6b [2] d8 69 [2] 9f 78 [2] d1 74 [2] dd 7e [2] ca 75 [2] d1 3b [2] ec }

  condition:
    any of them
}