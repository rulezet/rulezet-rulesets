rule TTP_XOR_MULT_DOSStub_d4a5 {
  strings:
    $key_d4a5 = { 80 cd [2] f4 d5 [2] b3 d7 [2] f4 c6 [2] ba ca [2] b6 c0 [2] a1 cb [2] ba 85 [2] 87 }

  condition:
    any of them
}