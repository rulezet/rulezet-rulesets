rule TTP_XOR_MULT_DOSStub_41a5 {
  strings:
    $key_41a5 = { 15 cd [2] 61 d5 [2] 26 d7 [2] 61 c6 [2] 2f ca [2] 23 c0 [2] 34 cb [2] 2f 85 [2] 12 }

  condition:
    any of them
}