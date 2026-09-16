rule TTP_XOR_MULT_DOSStub_b1a2 {
  strings:
    $key_b1a2 = { e5 ca [2] 91 d2 [2] d6 d0 [2] 91 c1 [2] df cd [2] d3 c7 [2] c4 cc [2] df 82 [2] e2 }

  condition:
    any of them
}