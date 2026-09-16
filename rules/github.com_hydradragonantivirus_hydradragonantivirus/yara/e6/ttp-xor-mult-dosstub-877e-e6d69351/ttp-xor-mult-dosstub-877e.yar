rule TTP_XOR_MULT_DOSStub_877e {
  strings:
    $key_877e = { d3 16 [2] a7 0e [2] e0 0c [2] a7 1d [2] e9 11 [2] e5 1b [2] f2 10 [2] e9 5e [2] d4 }

  condition:
    any of them
}