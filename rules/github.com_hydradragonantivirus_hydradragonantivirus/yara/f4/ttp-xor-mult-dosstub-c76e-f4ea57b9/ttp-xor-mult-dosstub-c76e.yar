rule TTP_XOR_MULT_DOSStub_c76e {
  strings:
    $key_c76e = { 93 06 [2] e7 1e [2] a0 1c [2] e7 0d [2] a9 01 [2] a5 0b [2] b2 00 [2] a9 4e [2] 94 }

  condition:
    any of them
}