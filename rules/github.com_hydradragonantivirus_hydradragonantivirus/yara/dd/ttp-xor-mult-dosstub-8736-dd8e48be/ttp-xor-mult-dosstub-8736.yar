rule TTP_XOR_MULT_DOSStub_8736 {
  strings:
    $key_8736 = { d3 5e [2] a7 46 [2] e0 44 [2] a7 55 [2] e9 59 [2] e5 53 [2] f2 58 [2] e9 16 [2] d4 }

  condition:
    any of them
}