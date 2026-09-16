rule TTP_XOR_MULT_DOSStub_20a5 {
  strings:
    $key_20a5 = { 74 cd [2] 00 d5 [2] 47 d7 [2] 00 c6 [2] 4e ca [2] 42 c0 [2] 55 cb [2] 4e 85 [2] 73 }

  condition:
    any of them
}