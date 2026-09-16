rule TTP_XOR_MULT_DOSStub_8739 {
  strings:
    $key_8739 = { d3 51 [2] a7 49 [2] e0 4b [2] a7 5a [2] e9 56 [2] e5 5c [2] f2 57 [2] e9 19 [2] d4 }

  condition:
    any of them
}