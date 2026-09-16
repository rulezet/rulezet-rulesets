rule TTP_XOR_MULT_DOSStub_c74b {
  strings:
    $key_c74b = { 93 23 [2] e7 3b [2] a0 39 [2] e7 28 [2] a9 24 [2] a5 2e [2] b2 25 [2] a9 6b [2] 94 }

  condition:
    any of them
}