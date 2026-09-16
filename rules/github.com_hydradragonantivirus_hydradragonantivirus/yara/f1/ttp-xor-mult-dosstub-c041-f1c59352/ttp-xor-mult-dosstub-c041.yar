rule TTP_XOR_MULT_DOSStub_c041 {
  strings:
    $key_c041 = { 94 29 [2] e0 31 [2] a7 33 [2] e0 22 [2] ae 2e [2] a2 24 [2] b5 2f [2] ae 61 [2] 93 }

  condition:
    any of them
}