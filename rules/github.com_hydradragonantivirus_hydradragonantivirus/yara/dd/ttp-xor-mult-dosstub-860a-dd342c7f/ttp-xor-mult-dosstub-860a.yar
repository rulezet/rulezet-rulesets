rule TTP_XOR_MULT_DOSStub_860a {
  strings:
    $key_860a = { d2 62 [2] a6 7a [2] e1 78 [2] a6 69 [2] e8 65 [2] e4 6f [2] f3 64 [2] e8 2a [2] d5 }

  condition:
    any of them
}