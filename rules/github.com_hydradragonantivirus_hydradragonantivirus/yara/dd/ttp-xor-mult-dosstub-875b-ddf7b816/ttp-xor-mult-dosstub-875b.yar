rule TTP_XOR_MULT_DOSStub_875b {
  strings:
    $key_875b = { d3 33 [2] a7 2b [2] e0 29 [2] a7 38 [2] e9 34 [2] e5 3e [2] f2 35 [2] e9 7b [2] d4 }

  condition:
    any of them
}