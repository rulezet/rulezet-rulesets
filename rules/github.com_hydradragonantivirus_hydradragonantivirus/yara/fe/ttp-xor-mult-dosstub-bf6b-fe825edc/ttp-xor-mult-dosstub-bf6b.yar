rule TTP_XOR_MULT_DOSStub_bf6b {
  strings:
    $key_bf6b = { eb 03 [2] 9f 1b [2] d8 19 [2] 9f 08 [2] d1 04 [2] dd 0e [2] ca 05 [2] d1 4b [2] ec }

  condition:
    any of them
}