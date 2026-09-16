rule TTP_XOR_MULT_DOSStub_31a5 {
  strings:
    $key_31a5 = { 65 cd [2] 11 d5 [2] 56 d7 [2] 11 c6 [2] 5f ca [2] 53 c0 [2] 44 cb [2] 5f 85 [2] 62 }

  condition:
    any of them
}