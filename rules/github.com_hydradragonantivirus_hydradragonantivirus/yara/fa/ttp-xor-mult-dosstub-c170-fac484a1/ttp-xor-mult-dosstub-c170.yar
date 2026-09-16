rule TTP_XOR_MULT_DOSStub_c170 {
  strings:
    $key_c170 = { 95 18 [2] e1 00 [2] a6 02 [2] e1 13 [2] af 1f [2] a3 15 [2] b4 1e [2] af 50 [2] 92 }

  condition:
    any of them
}