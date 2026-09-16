rule TTP_XOR_MULT_DOSStub_8752 {
  strings:
    $key_8752 = { d3 3a [2] a7 22 [2] e0 20 [2] a7 31 [2] e9 3d [2] e5 37 [2] f2 3c [2] e9 72 [2] d4 }

  condition:
    any of them
}