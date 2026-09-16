rule TTP_XOR_MULT_DOSStub_c3f0 {
  strings:
    $key_c3f0 = { 97 98 [2] e3 80 [2] a4 82 [2] e3 93 [2] ad 9f [2] a1 95 [2] b6 9e [2] ad d0 [2] 90 }

  condition:
    any of them
}