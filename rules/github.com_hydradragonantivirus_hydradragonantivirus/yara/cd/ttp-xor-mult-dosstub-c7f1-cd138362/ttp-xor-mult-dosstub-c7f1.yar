rule TTP_XOR_MULT_DOSStub_c7f1 {
  strings:
    $key_c7f1 = { 93 99 [2] e7 81 [2] a0 83 [2] e7 92 [2] a9 9e [2] a5 94 [2] b2 9f [2] a9 d1 [2] 94 }

  condition:
    any of them
}