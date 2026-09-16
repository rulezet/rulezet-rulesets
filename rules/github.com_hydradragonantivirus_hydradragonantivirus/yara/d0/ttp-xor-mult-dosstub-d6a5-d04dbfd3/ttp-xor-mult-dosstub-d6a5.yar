rule TTP_XOR_MULT_DOSStub_d6a5 {
  strings:
    $key_d6a5 = { 82 cd [2] f6 d5 [2] b1 d7 [2] f6 c6 [2] b8 ca [2] b4 c0 [2] a3 cb [2] b8 85 [2] 85 }

  condition:
    any of them
}