rule TTP_XOR_MULT_DOSStub_8758 {
  strings:
    $key_8758 = { d3 30 [2] a7 28 [2] e0 2a [2] a7 3b [2] e9 37 [2] e5 3d [2] f2 36 [2] e9 78 [2] d4 }

  condition:
    any of them
}