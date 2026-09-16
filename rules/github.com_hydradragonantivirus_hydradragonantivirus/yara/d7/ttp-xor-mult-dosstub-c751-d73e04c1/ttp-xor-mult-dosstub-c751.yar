rule TTP_XOR_MULT_DOSStub_c751 {
  strings:
    $key_c751 = { 93 39 [2] e7 21 [2] a0 23 [2] e7 32 [2] a9 3e [2] a5 34 [2] b2 3f [2] a9 71 [2] 94 }

  condition:
    any of them
}