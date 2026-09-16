rule TTP_XOR_MULT_DOSStub_c04e {
  strings:
    $key_c04e = { 94 26 [2] e0 3e [2] a7 3c [2] e0 2d [2] ae 21 [2] a2 2b [2] b5 20 [2] ae 6e [2] 93 }

  condition:
    any of them
}