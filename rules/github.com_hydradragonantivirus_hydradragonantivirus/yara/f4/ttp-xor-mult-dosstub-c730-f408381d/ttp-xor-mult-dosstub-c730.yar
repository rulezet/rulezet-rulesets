rule TTP_XOR_MULT_DOSStub_c730 {
  strings:
    $key_c730 = { 93 58 [2] e7 40 [2] a0 42 [2] e7 53 [2] a9 5f [2] a5 55 [2] b2 5e [2] a9 10 [2] 94 }

  condition:
    any of them
}