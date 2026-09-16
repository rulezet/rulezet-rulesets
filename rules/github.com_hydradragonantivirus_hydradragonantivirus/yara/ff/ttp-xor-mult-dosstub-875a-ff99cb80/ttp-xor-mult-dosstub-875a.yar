rule TTP_XOR_MULT_DOSStub_875a {
  strings:
    $key_875a = { d3 32 [2] a7 2a [2] e0 28 [2] a7 39 [2] e9 35 [2] e5 3f [2] f2 34 [2] e9 7a [2] d4 }

  condition:
    any of them
}