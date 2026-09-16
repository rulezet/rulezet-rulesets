rule TTP_XOR_MULT_DOSStub_c18b {
  strings:
    $key_c18b = { 95 e3 [2] e1 fb [2] a6 f9 [2] e1 e8 [2] af e4 [2] a3 ee [2] b4 e5 [2] af ab [2] 92 }

  condition:
    any of them
}