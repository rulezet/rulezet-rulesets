rule TTP_XOR_MULT_DOSStub_bfbb {
  strings:
    $key_bfbb = { eb d3 [2] 9f cb [2] d8 c9 [2] 9f d8 [2] d1 d4 [2] dd de [2] ca d5 [2] d1 9b [2] ec }

  condition:
    any of them
}