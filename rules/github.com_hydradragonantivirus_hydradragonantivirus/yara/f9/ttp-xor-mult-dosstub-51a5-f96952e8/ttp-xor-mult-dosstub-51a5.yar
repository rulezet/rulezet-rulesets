rule TTP_XOR_MULT_DOSStub_51a5 {
  strings:
    $key_51a5 = { 05 cd [2] 71 d5 [2] 36 d7 [2] 71 c6 [2] 3f ca [2] 33 c0 [2] 24 cb [2] 3f 85 [2] 02 }

  condition:
    any of them
}