rule TTP_XOR_MULT_DOSStub_c77d {
  strings:
    $key_c77d = { 93 15 [2] e7 0d [2] a0 0f [2] e7 1e [2] a9 12 [2] a5 18 [2] b2 13 [2] a9 5d [2] 94 }

  condition:
    any of them
}