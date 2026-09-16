rule TTP_XOR_MULT_DOSStub_c73d {
  strings:
    $key_c73d = { 93 55 [2] e7 4d [2] a0 4f [2] e7 5e [2] a9 52 [2] a5 58 [2] b2 53 [2] a9 1d [2] 94 }

  condition:
    any of them
}