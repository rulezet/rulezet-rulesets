rule TTP_XOR_MULT_DOSStub_bfdd {
  strings:
    $key_bfdd = { eb b5 [2] 9f ad [2] d8 af [2] 9f be [2] d1 b2 [2] dd b8 [2] ca b3 [2] d1 fd [2] ec }

  condition:
    any of them
}