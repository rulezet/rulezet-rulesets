rule TTP_XOR_MULT_DOSStub_877b {
  strings:
    $key_877b = { d3 13 [2] a7 0b [2] e0 09 [2] a7 18 [2] e9 14 [2] e5 1e [2] f2 15 [2] e9 5b [2] d4 }

  condition:
    any of them
}