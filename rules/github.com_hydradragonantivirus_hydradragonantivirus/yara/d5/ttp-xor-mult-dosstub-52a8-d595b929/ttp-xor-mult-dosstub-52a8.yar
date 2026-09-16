rule TTP_XOR_MULT_DOSStub_52a8 {
  strings:
    $key_52a8 = { 06 c0 [2] 72 d8 [2] 35 da [2] 72 cb [2] 3c c7 [2] 30 cd [2] 27 c6 [2] 3c 88 [2] 01 }

  condition:
    any of them
}