rule TTP_XOR_MULT_DOSStub_860b {
  strings:
    $key_860b = { d2 63 [2] a6 7b [2] e1 79 [2] a6 68 [2] e8 64 [2] e4 6e [2] f3 65 [2] e8 2b [2] d5 }

  condition:
    any of them
}