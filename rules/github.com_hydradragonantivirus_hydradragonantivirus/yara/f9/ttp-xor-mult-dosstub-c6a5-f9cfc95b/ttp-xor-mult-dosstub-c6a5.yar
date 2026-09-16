rule TTP_XOR_MULT_DOSStub_c6a5 {
  strings:
    $key_c6a5 = { 92 cd [2] e6 d5 [2] a1 d7 [2] e6 c6 [2] a8 ca [2] a4 c0 [2] b3 cb [2] a8 85 [2] 95 }

  condition:
    any of them
}