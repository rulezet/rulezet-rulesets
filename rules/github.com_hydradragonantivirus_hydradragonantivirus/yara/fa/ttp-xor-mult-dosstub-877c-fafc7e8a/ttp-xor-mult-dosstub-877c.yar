rule TTP_XOR_MULT_DOSStub_877c {
  strings:
    $key_877c = { d3 14 [2] a7 0c [2] e0 0e [2] a7 1f [2] e9 13 [2] e5 19 [2] f2 12 [2] e9 5c [2] d4 }

  condition:
    any of them
}