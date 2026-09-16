rule TTP_XOR_MULT_DOSStub_c71e {
  strings:
    $key_c71e = { 93 76 [2] e7 6e [2] a0 6c [2] e7 7d [2] a9 71 [2] a5 7b [2] b2 70 [2] a9 3e [2] 94 }

  condition:
    any of them
}