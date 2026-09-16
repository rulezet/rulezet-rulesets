rule TTP_XOR_MULT_DOSStub_21a8 {
  strings:
    $key_21a8 = { 75 c0 [2] 01 d8 [2] 46 da [2] 01 cb [2] 4f c7 [2] 43 cd [2] 54 c6 [2] 4f 88 [2] 72 }

  condition:
    any of them
}