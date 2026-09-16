rule TTP_XOR_MULT_DOSStub_b1a9 {
  strings:
    $key_b1a9 = { e5 c1 [2] 91 d9 [2] d6 db [2] 91 ca [2] df c6 [2] d3 cc [2] c4 c7 [2] df 89 [2] e2 }

  condition:
    any of them
}