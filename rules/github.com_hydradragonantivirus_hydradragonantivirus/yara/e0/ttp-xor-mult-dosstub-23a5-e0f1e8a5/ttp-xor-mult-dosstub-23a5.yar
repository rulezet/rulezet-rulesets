rule TTP_XOR_MULT_DOSStub_23a5 {
  strings:
    $key_23a5 = { 77 cd [2] 03 d5 [2] 44 d7 [2] 03 c6 [2] 4d ca [2] 41 c0 [2] 56 cb [2] 4d 85 [2] 70 }

  condition:
    any of them
}