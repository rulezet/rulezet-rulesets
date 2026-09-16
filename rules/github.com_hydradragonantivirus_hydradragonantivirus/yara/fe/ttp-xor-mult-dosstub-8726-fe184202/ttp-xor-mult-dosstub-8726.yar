rule TTP_XOR_MULT_DOSStub_8726 {
  strings:
    $key_8726 = { d3 4e [2] a7 56 [2] e0 54 [2] a7 45 [2] e9 49 [2] e5 43 [2] f2 48 [2] e9 06 [2] d4 }

  condition:
    any of them
}