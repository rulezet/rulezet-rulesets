rule TTP_XOR_MULT_DOSStub_c726 {
  strings:
    $key_c726 = { 93 4e [2] e7 56 [2] a0 54 [2] e7 45 [2] a9 49 [2] a5 43 [2] b2 48 [2] a9 06 [2] 94 }

  condition:
    any of them
}