rule TTP_XOR_MULT_DOSStub_63a5 {
  strings:
    $key_63a5 = { 37 cd [2] 43 d5 [2] 04 d7 [2] 43 c6 [2] 0d ca [2] 01 c0 [2] 16 cb [2] 0d 85 [2] 30 }

  condition:
    any of them
}