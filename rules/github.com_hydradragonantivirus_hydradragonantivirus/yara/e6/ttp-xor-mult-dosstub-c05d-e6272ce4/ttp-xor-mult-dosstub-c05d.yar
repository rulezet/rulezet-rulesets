rule TTP_XOR_MULT_DOSStub_c05d {
  strings:
    $key_c05d = { 94 35 [2] e0 2d [2] a7 2f [2] e0 3e [2] ae 32 [2] a2 38 [2] b5 33 [2] ae 7d [2] 93 }

  condition:
    any of them
}