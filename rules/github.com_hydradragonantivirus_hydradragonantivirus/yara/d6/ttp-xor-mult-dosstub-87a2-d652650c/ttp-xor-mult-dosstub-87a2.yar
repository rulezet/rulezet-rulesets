rule TTP_XOR_MULT_DOSStub_87a2 {
  strings:
    $key_87a2 = { d3 ca [2] a7 d2 [2] e0 d0 [2] a7 c1 [2] e9 cd [2] e5 c7 [2] f2 cc [2] e9 82 [2] d4 }

  condition:
    any of them
}