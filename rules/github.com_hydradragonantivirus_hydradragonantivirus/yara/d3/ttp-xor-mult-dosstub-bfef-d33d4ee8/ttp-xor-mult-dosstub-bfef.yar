rule TTP_XOR_MULT_DOSStub_bfef {
  strings:
    $key_bfef = { eb 87 [2] 9f 9f [2] d8 9d [2] 9f 8c [2] d1 80 [2] dd 8a [2] ca 81 [2] d1 cf [2] ec }

  condition:
    any of them
}