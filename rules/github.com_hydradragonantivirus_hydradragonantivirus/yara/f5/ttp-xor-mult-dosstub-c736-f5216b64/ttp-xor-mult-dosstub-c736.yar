rule TTP_XOR_MULT_DOSStub_c736 {
  strings:
    $key_c736 = { 93 5e [2] e7 46 [2] a0 44 [2] e7 55 [2] a9 59 [2] a5 53 [2] b2 58 [2] a9 16 [2] 94 }

  condition:
    any of them
}