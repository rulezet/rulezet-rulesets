rule TTP_XOR_MULT_DOSStub_8733 {
  strings:
    $key_8733 = { d3 5b [2] a7 43 [2] e0 41 [2] a7 50 [2] e9 5c [2] e5 56 [2] f2 5d [2] e9 13 [2] d4 }

  condition:
    any of them
}