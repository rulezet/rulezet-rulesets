rule TTP_XOR_MULT_DOSStub_b9dd {
  strings:
    $key_b9dd = { ed b5 [2] 99 ad [2] de af [2] 99 be [2] d7 b2 [2] db b8 [2] cc b3 [2] d7 fd [2] ea }

  condition:
    any of them
}