rule TTP_XOR_MULT_DOSStub_c1f0 {
  strings:
    $key_c1f0 = { 95 98 [2] e1 80 [2] a6 82 [2] e1 93 [2] af 9f [2] a3 95 [2] b4 9e [2] af d0 [2] 92 }

  condition:
    any of them
}