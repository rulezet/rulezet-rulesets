rule TTP_XOR_MULT_DOSStub_c161 {
  strings:
    $key_c161 = { 95 09 [2] e1 11 [2] a6 13 [2] e1 02 [2] af 0e [2] a3 04 [2] b4 0f [2] af 41 [2] 92 }

  condition:
    any of them
}