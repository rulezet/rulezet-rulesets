rule TTP_XOR_MULT_DOSStub_8717 {
  strings:
    $key_8717 = { d3 7f [2] a7 67 [2] e0 65 [2] a7 74 [2] e9 78 [2] e5 72 [2] f2 79 [2] e9 37 [2] d4 }

  condition:
    any of them
}