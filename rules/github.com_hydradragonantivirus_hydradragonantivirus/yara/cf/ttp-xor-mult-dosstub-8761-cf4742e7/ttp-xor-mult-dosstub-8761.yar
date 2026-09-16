rule TTP_XOR_MULT_DOSStub_8761 {
  strings:
    $key_8761 = { d3 09 [2] a7 11 [2] e0 13 [2] a7 02 [2] e9 0e [2] e5 04 [2] f2 0f [2] e9 41 [2] d4 }

  condition:
    any of them
}