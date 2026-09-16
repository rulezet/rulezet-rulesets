rule TTP_XOR_MULT_DOSStub_23b9 {
  strings:
    $key_23b9 = { 77 d1 [2] 03 c9 [2] 44 cb [2] 03 da [2] 4d d6 [2] 41 dc [2] 56 d7 [2] 4d 99 [2] 70 }

  condition:
    any of them
}