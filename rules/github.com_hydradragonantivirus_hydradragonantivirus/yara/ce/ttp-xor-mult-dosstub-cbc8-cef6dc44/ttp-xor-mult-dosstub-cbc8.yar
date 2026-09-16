rule TTP_XOR_MULT_DOSStub_cbc8 {
  strings:
    $key_cbc8 = { 9f a0 [2] eb b8 [2] ac ba [2] eb ab [2] a5 a7 [2] a9 ad [2] be a6 [2] a5 e8 [2] 98 }

  condition:
    any of them
}