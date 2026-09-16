rule TTP_XOR_MULT_DOSStub_65b2 {
  strings:
    $key_65b2 = { 31 da [2] 45 c2 [2] 02 c0 [2] 45 d1 [2] 0b dd [2] 07 d7 [2] 10 dc [2] 0b 92 [2] 36 }

  condition:
    any of them
}