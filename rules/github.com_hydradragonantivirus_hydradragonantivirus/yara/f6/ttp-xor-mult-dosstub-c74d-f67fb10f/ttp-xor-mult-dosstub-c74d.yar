rule TTP_XOR_MULT_DOSStub_c74d {
  strings:
    $key_c74d = { 93 25 [2] e7 3d [2] a0 3f [2] e7 2e [2] a9 22 [2] a5 28 [2] b2 23 [2] a9 6d [2] 94 }

  condition:
    any of them
}