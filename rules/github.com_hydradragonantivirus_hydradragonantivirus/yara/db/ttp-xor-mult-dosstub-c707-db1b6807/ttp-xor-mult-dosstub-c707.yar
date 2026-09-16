rule TTP_XOR_MULT_DOSStub_c707 {
  strings:
    $key_c707 = { 93 6f [2] e7 77 [2] a0 75 [2] e7 64 [2] a9 68 [2] a5 62 [2] b2 69 [2] a9 27 [2] 94 }

  condition:
    any of them
}