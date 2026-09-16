rule TTP_XOR_MULT_DOSStub_c176 {
  strings:
    $key_c176 = { 95 1e [2] e1 06 [2] a6 04 [2] e1 15 [2] af 19 [2] a3 13 [2] b4 18 [2] af 56 [2] 92 }

  condition:
    any of them
}