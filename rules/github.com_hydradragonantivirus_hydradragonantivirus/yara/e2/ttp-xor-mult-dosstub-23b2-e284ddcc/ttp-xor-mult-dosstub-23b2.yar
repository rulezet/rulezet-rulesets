rule TTP_XOR_MULT_DOSStub_23b2 {
  strings:
    $key_23b2 = { 77 da [2] 03 c2 [2] 44 c0 [2] 03 d1 [2] 4d dd [2] 41 d7 [2] 56 dc [2] 4d 92 [2] 70 }

  condition:
    any of them
}