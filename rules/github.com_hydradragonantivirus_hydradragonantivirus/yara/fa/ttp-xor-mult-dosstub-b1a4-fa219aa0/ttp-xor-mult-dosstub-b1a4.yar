rule TTP_XOR_MULT_DOSStub_b1a4 {
  strings:
    $key_b1a4 = { e5 cc [2] 91 d4 [2] d6 d6 [2] 91 c7 [2] df cb [2] d3 c1 [2] c4 ca [2] df 84 [2] e2 }

  condition:
    any of them
}