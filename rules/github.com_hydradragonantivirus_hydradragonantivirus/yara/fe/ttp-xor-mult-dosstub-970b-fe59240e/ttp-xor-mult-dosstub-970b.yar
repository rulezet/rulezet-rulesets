rule TTP_XOR_MULT_DOSStub_970b {
  strings:
    $key_970b = { c3 63 [2] b7 7b [2] f0 79 [2] b7 68 [2] f9 64 [2] f5 6e [2] e2 65 [2] f9 2b [2] c4 }

  condition:
    any of them
}