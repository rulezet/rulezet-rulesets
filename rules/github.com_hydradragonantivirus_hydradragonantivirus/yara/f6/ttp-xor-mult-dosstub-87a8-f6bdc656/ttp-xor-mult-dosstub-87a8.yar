rule TTP_XOR_MULT_DOSStub_87a8 {
  strings:
    $key_87a8 = { d3 c0 [2] a7 d8 [2] e0 da [2] a7 cb [2] e9 c7 [2] e5 cd [2] f2 c6 [2] e9 88 [2] d4 }

  condition:
    any of them
}