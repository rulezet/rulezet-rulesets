rule TTP_XOR_MULT_DOSStub_87b7 {
  strings:
    $key_87b7 = { d3 df [2] a7 c7 [2] e0 c5 [2] a7 d4 [2] e9 d8 [2] e5 d2 [2] f2 d9 [2] e9 97 [2] d4 }

  condition:
    any of them
}