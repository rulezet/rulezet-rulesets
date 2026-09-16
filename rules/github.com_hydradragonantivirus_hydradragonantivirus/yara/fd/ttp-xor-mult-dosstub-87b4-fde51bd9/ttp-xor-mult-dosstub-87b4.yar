rule TTP_XOR_MULT_DOSStub_87b4 {
  strings:
    $key_87b4 = { d3 dc [2] a7 c4 [2] e0 c6 [2] a7 d7 [2] e9 db [2] e5 d1 [2] f2 da [2] e9 94 [2] d4 }

  condition:
    any of them
}