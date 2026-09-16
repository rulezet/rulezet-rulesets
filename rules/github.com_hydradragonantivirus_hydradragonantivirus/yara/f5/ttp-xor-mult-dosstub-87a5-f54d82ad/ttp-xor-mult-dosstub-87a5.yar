rule TTP_XOR_MULT_DOSStub_87a5 {
  strings:
    $key_87a5 = { d3 cd [2] a7 d5 [2] e0 d7 [2] a7 c6 [2] e9 ca [2] e5 c0 [2] f2 cb [2] e9 85 [2] d4 }

  condition:
    any of them
}