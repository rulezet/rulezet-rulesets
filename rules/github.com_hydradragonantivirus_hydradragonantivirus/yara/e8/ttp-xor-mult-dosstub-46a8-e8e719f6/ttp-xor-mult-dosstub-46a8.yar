rule TTP_XOR_MULT_DOSStub_46a8 {
  strings:
    $key_46a8 = { 12 c0 [2] 66 d8 [2] 21 da [2] 66 cb [2] 28 c7 [2] 24 cd [2] 33 c6 [2] 28 88 [2] 15 }

  condition:
    any of them
}