rule TTP_XOR_MULT_DOSStub_03a8 {
  strings:
    $key_03a8 = { 57 c0 [2] 23 d8 [2] 64 da [2] 23 cb [2] 6d c7 [2] 61 cd [2] 76 c6 [2] 6d 88 [2] 50 }

  condition:
    any of them
}