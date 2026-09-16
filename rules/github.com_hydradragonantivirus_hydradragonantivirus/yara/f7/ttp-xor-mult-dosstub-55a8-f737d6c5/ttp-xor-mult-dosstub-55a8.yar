rule TTP_XOR_MULT_DOSStub_55a8 {
  strings:
    $key_55a8 = { 01 c0 [2] 75 d8 [2] 32 da [2] 75 cb [2] 3b c7 [2] 37 cd [2] 20 c6 [2] 3b 88 [2] 06 }

  condition:
    any of them
}