rule TTP_XOR_MULT_DOSStub_bf1c {
  strings:
    $key_bf1c = { eb 74 [2] 9f 6c [2] d8 6e [2] 9f 7f [2] d1 73 [2] dd 79 [2] ca 72 [2] d1 3c [2] ec }

  condition:
    any of them
}