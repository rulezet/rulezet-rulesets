rule TTP_XOR_MULT_DOSStub_c111 {
  strings:
    $key_c111 = { 95 79 [2] e1 61 [2] a6 63 [2] e1 72 [2] af 7e [2] a3 74 [2] b4 7f [2] af 31 [2] 92 }

  condition:
    any of them
}