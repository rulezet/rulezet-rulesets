rule TTP_XOR_MULT_DOSStub_04a5 {
  strings:
    $key_04a5 = { 50 cd [2] 24 d5 [2] 63 d7 [2] 24 c6 [2] 6a ca [2] 66 c0 [2] 71 cb [2] 6a 85 [2] 57 }

  condition:
    any of them
}