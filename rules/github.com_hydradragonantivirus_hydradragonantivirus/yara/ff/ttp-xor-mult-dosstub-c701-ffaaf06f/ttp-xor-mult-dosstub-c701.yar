rule TTP_XOR_MULT_DOSStub_c701 {
  strings:
    $key_c701 = { 93 69 [2] e7 71 [2] a0 73 [2] e7 62 [2] a9 6e [2] a5 64 [2] b2 6f [2] a9 21 [2] 94 }

  condition:
    any of them
}