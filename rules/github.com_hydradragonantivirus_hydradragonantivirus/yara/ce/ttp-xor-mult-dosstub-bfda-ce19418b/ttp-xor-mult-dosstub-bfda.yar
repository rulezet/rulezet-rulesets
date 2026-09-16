rule TTP_XOR_MULT_DOSStub_bfda {
  strings:
    $key_bfda = { eb b2 [2] 9f aa [2] d8 a8 [2] 9f b9 [2] d1 b5 [2] dd bf [2] ca b4 [2] d1 fa [2] ec }

  condition:
    any of them
}