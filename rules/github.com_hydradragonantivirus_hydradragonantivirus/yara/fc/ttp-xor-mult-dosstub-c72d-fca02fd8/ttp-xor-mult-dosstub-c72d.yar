rule TTP_XOR_MULT_DOSStub_c72d {
  strings:
    $key_c72d = { 93 45 [2] e7 5d [2] a0 5f [2] e7 4e [2] a9 42 [2] a5 48 [2] b2 43 [2] a9 0d [2] 94 }

  condition:
    any of them
}