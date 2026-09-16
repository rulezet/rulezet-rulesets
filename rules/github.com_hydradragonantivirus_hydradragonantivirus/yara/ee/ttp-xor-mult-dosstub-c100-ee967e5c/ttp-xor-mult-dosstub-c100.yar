rule TTP_XOR_MULT_DOSStub_c100 {
  strings:
    $key_c100 = { 95 68 [2] e1 70 [2] a6 72 [2] e1 63 [2] af 6f [2] a3 65 [2] b4 6e [2] af 20 [2] 92 }

  condition:
    any of them
}