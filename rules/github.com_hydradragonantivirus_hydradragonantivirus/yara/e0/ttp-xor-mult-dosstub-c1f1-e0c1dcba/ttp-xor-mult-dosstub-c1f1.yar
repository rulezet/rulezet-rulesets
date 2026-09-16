rule TTP_XOR_MULT_DOSStub_c1f1 {
  strings:
    $key_c1f1 = { 95 99 [2] e1 81 [2] a6 83 [2] e1 92 [2] af 9e [2] a3 94 [2] b4 9f [2] af d1 [2] 92 }

  condition:
    any of them
}