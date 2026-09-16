rule TTP_XOR_MULT_DOSStub_8777 {
  strings:
    $key_8777 = { d3 1f [2] a7 07 [2] e0 05 [2] a7 14 [2] e9 18 [2] e5 12 [2] f2 19 [2] e9 57 [2] d4 }

  condition:
    any of them
}