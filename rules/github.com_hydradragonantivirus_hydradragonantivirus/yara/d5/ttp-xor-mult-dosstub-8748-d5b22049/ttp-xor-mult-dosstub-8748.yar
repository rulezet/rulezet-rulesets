rule TTP_XOR_MULT_DOSStub_8748 {
  strings:
    $key_8748 = { d3 20 [2] a7 38 [2] e0 3a [2] a7 2b [2] e9 27 [2] e5 2d [2] f2 26 [2] e9 68 [2] d4 }

  condition:
    any of them
}