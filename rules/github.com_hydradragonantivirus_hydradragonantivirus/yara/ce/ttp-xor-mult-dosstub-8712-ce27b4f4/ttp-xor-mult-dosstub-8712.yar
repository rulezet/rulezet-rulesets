rule TTP_XOR_MULT_DOSStub_8712 {
  strings:
    $key_8712 = { d3 7a [2] a7 62 [2] e0 60 [2] a7 71 [2] e9 7d [2] e5 77 [2] f2 7c [2] e9 32 [2] d4 }

  condition:
    any of them
}