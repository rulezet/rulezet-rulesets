rule TTP_XOR_MULT_DOSStub_bffd {
  strings:
    $key_bffd = { eb 95 [2] 9f 8d [2] d8 8f [2] 9f 9e [2] d1 92 [2] dd 98 [2] ca 93 [2] d1 dd [2] ec }

  condition:
    any of them
}