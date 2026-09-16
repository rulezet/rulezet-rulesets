rule TTP_XOR_MULT_DOSStub_bf28 {
  strings:
    $key_bf28 = { eb 40 [2] 9f 58 [2] d8 5a [2] 9f 4b [2] d1 47 [2] dd 4d [2] ca 46 [2] d1 08 [2] ec }

  condition:
    any of them
}