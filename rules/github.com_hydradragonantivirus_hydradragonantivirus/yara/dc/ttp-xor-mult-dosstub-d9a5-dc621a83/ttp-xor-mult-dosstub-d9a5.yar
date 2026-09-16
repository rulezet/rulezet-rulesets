rule TTP_XOR_MULT_DOSStub_d9a5 {
  strings:
    $key_d9a5 = { 8d cd [2] f9 d5 [2] be d7 [2] f9 c6 [2] b7 ca [2] bb c0 [2] ac cb [2] b7 85 [2] 8a }

  condition:
    any of them
}