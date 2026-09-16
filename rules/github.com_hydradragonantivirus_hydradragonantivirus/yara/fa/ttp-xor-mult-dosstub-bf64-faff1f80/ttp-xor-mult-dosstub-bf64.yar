rule TTP_XOR_MULT_DOSStub_bf64 {
  strings:
    $key_bf64 = { eb 0c [2] 9f 14 [2] d8 16 [2] 9f 07 [2] d1 0b [2] dd 01 [2] ca 0a [2] d1 44 [2] ec }

  condition:
    any of them
}