rule TTP_XOR_MULT_DOSStub_c141 {
  strings:
    $key_c141 = { 95 29 [2] e1 31 [2] a6 33 [2] e1 22 [2] af 2e [2] a3 24 [2] b4 2f [2] af 61 [2] 92 }

  condition:
    any of them
}