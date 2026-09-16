rule TTP_XOR_MULT_DOSStub_870b {
  strings:
    $key_870b = { d3 63 [2] a7 7b [2] e0 79 [2] a7 68 [2] e9 64 [2] e5 6e [2] f2 65 [2] e9 2b [2] d4 }

  condition:
    any of them
}