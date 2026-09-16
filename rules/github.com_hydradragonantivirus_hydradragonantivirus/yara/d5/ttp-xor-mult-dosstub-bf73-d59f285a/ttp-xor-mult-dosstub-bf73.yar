rule TTP_XOR_MULT_DOSStub_bf73 {
  strings:
    $key_bf73 = { eb 1b [2] 9f 03 [2] d8 01 [2] 9f 10 [2] d1 1c [2] dd 16 [2] ca 1d [2] d1 53 [2] ec }

  condition:
    any of them
}