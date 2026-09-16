rule TTP_XOR_MULT_DOSStub_8750 {
  strings:
    $key_8750 = { d3 38 [2] a7 20 [2] e0 22 [2] a7 33 [2] e9 3f [2] e5 35 [2] f2 3e [2] e9 70 [2] d4 }

  condition:
    any of them
}