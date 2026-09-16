rule TTP_XOR_MULT_DOSStub_22a5 {
  strings:
    $key_22a5 = { 76 cd [2] 02 d5 [2] 45 d7 [2] 02 c6 [2] 4c ca [2] 40 c0 [2] 57 cb [2] 4c 85 [2] 71 }

  condition:
    any of them
}