rule TTP_XOR_MULT_DOSStub_c716 {
  strings:
    $key_c716 = { 93 7e [2] e7 66 [2] a0 64 [2] e7 75 [2] a9 79 [2] a5 73 [2] b2 78 [2] a9 36 [2] 94 }

  condition:
    any of them
}