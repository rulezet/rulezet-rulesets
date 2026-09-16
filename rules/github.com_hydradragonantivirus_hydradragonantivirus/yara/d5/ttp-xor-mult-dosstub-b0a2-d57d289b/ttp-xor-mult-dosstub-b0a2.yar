rule TTP_XOR_MULT_DOSStub_b0a2 {
  strings:
    $key_b0a2 = { e4 ca [2] 90 d2 [2] d7 d0 [2] 90 c1 [2] de cd [2] d2 c7 [2] c5 cc [2] de 82 [2] e3 }

  condition:
    any of them
}