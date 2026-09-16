rule TTP_XOR_MULT_DOSStub_c127 {
  strings:
    $key_c127 = { 95 4f [2] e1 57 [2] a6 55 [2] e1 44 [2] af 48 [2] a3 42 [2] b4 49 [2] af 07 [2] 92 }

  condition:
    any of them
}