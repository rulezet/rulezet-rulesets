rule TTP_XOR_MULT_DOSStub_871a {
  strings:
    $key_871a = { d3 72 [2] a7 6a [2] e0 68 [2] a7 79 [2] e9 75 [2] e5 7f [2] f2 74 [2] e9 3a [2] d4 }

  condition:
    any of them
}