rule TTP_XOR_MULT_DOSStub_872c {
  strings:
    $key_872c = { d3 44 [2] a7 5c [2] e0 5e [2] a7 4f [2] e9 43 [2] e5 49 [2] f2 42 [2] e9 0c [2] d4 }

  condition:
    any of them
}