rule TTP_XOR_MULT_DOSStub_bdb1 {
  strings:
    $key_bdb1 = { e9 d9 [2] 9d c1 [2] da c3 [2] 9d d2 [2] d3 de [2] df d4 [2] c8 df [2] d3 91 [2] ee }

  condition:
    any of them
}