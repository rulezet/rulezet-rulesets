rule TTP_XOR_MULT_DOSStub_d5a5 {
  strings:
    $key_d5a5 = { 81 cd [2] f5 d5 [2] b2 d7 [2] f5 c6 [2] bb ca [2] b7 c0 [2] a0 cb [2] bb 85 [2] 86 }

  condition:
    any of them
}