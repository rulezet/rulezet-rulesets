rule TTP_XOR_MULT_DOSStub_c75a {
  strings:
    $key_c75a = { 93 32 [2] e7 2a [2] a0 28 [2] e7 39 [2] a9 35 [2] a5 3f [2] b2 34 [2] a9 7a [2] 94 }

  condition:
    any of them
}