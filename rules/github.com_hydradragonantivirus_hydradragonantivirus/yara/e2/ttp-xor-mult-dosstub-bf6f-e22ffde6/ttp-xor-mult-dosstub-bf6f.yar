rule TTP_XOR_MULT_DOSStub_bf6f {
  strings:
    $key_bf6f = { eb 07 [2] 9f 1f [2] d8 1d [2] 9f 0c [2] d1 00 [2] dd 0a [2] ca 01 [2] d1 4f [2] ec }

  condition:
    any of them
}