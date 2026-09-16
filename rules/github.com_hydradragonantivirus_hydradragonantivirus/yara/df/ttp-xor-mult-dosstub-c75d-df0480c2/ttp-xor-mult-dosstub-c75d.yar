rule TTP_XOR_MULT_DOSStub_c75d {
  strings:
    $key_c75d = { 93 35 [2] e7 2d [2] a0 2f [2] e7 3e [2] a9 32 [2] a5 38 [2] b2 33 [2] a9 7d [2] 94 }

  condition:
    any of them
}