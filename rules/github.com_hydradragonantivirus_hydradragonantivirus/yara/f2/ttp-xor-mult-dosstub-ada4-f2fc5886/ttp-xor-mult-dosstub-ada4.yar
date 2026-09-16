rule TTP_XOR_MULT_DOSStub_ada4 {
  strings:
    $key_ada4 = { f9 cc [2] 8d d4 [2] ca d6 [2] 8d c7 [2] c3 cb [2] cf c1 [2] d8 ca [2] c3 84 [2] fe }

  condition:
    any of them
}