rule TTP_XOR_MULT_DOSStub_c167 {
  strings:
    $key_c167 = { 95 0f [2] e1 17 [2] a6 15 [2] e1 04 [2] af 08 [2] a3 02 [2] b4 09 [2] af 47 [2] 92 }

  condition:
    any of them
}