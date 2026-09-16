rule TTP_XOR_MULT_DOSStub_8757 {
  strings:
    $key_8757 = { d3 3f [2] a7 27 [2] e0 25 [2] a7 34 [2] e9 38 [2] e5 32 [2] f2 39 [2] e9 77 [2] d4 }

  condition:
    any of them
}