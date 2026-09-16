rule TTP_XOR_MULT_DOSStub_c7a5 {
  strings:
    $key_c7a5 = { 93 cd [2] e7 d5 [2] a0 d7 [2] e7 c6 [2] a9 ca [2] a5 c0 [2] b2 cb [2] a9 85 [2] 94 }

  condition:
    any of them
}