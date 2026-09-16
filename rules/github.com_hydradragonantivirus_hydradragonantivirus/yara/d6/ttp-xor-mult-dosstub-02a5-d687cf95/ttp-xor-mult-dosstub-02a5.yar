rule TTP_XOR_MULT_DOSStub_02a5 {
  strings:
    $key_02a5 = { 56 cd [2] 22 d5 [2] 65 d7 [2] 22 c6 [2] 6c ca [2] 60 c0 [2] 77 cb [2] 6c 85 [2] 51 }

  condition:
    any of them
}