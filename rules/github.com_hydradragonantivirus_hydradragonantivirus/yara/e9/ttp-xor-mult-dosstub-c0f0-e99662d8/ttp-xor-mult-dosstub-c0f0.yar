rule TTP_XOR_MULT_DOSStub_c0f0 {
  strings:
    $key_c0f0 = { 94 98 [2] e0 80 [2] a7 82 [2] e0 93 [2] ae 9f [2] a2 95 [2] b5 9e [2] ae d0 [2] 93 }

  condition:
    any of them
}