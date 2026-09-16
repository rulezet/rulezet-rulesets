rule TTP_XOR_MULT_DOSStub_8749 {
  strings:
    $key_8749 = { d3 21 [2] a7 39 [2] e0 3b [2] a7 2a [2] e9 26 [2] e5 2c [2] f2 27 [2] e9 69 [2] d4 }

  condition:
    any of them
}