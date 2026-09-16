rule TTP_XOR_MULT_DOSStub_31a8 {
  strings:
    $key_31a8 = { 65 c0 [2] 11 d8 [2] 56 da [2] 11 cb [2] 5f c7 [2] 53 cd [2] 44 c6 [2] 5f 88 [2] 62 }

  condition:
    any of them
}