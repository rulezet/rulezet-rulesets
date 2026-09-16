rule TTP_XOR_MULT_DOSStub_c6f6 {
  strings:
    $key_c6f6 = { 92 9e [2] e6 86 [2] a1 84 [2] e6 95 [2] a8 99 [2] a4 93 [2] b3 98 [2] a8 d6 [2] 95 }

  condition:
    any of them
}