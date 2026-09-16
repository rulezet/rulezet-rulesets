rule TTP_XOR_MULT_DOSStub_c1e7 {
  strings:
    $key_c1e7 = { 95 8f [2] e1 97 [2] a6 95 [2] e1 84 [2] af 88 [2] a3 82 [2] b4 89 [2] af c7 [2] 92 }

  condition:
    any of them
}