rule TTP_XOR_MULT_DOSStub_87a3 {
  strings:
    $key_87a3 = { d3 cb [2] a7 d3 [2] e0 d1 [2] a7 c0 [2] e9 cc [2] e5 c6 [2] f2 cd [2] e9 83 [2] d4 }

  condition:
    any of them
}