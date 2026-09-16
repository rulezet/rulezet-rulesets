rule TTP_XOR_MULT_DOSStub_47a5 {
  strings:
    $key_47a5 = { 13 cd [2] 67 d5 [2] 20 d7 [2] 67 c6 [2] 29 ca [2] 25 c0 [2] 32 cb [2] 29 85 [2] 14 }

  condition:
    any of them
}