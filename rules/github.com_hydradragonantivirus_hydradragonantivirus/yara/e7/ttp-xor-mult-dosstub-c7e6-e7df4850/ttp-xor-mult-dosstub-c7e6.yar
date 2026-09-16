rule TTP_XOR_MULT_DOSStub_c7e6 {
  strings:
    $key_c7e6 = { 93 8e [2] e7 96 [2] a0 94 [2] e7 85 [2] a9 89 [2] a5 83 [2] b2 88 [2] a9 c6 [2] 94 }

  condition:
    any of them
}