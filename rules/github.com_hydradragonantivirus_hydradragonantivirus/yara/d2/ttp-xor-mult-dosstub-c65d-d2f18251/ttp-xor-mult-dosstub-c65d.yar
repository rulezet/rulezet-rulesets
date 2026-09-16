rule TTP_XOR_MULT_DOSStub_c65d {
  strings:
    $key_c65d = { 92 35 [2] e6 2d [2] a1 2f [2] e6 3e [2] a8 32 [2] a4 38 [2] b3 33 [2] a8 7d [2] 95 }

  condition:
    any of them
}