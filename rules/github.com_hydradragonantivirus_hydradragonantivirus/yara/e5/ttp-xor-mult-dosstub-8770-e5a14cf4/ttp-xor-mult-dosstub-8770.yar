rule TTP_XOR_MULT_DOSStub_8770 {
  strings:
    $key_8770 = { d3 18 [2] a7 00 [2] e0 02 [2] a7 13 [2] e9 1f [2] e5 15 [2] f2 1e [2] e9 50 [2] d4 }

  condition:
    any of them
}