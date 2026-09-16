rule TTP_XOR_MULT_DOSStub_75a5 {
  strings:
    $key_75a5 = { 21 cd [2] 55 d5 [2] 12 d7 [2] 55 c6 [2] 1b ca [2] 17 c0 [2] 00 cb [2] 1b 85 [2] 26 }

  condition:
    any of them
}