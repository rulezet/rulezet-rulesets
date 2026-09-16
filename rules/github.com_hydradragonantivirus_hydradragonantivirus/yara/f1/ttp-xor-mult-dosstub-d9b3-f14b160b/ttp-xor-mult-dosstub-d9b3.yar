rule TTP_XOR_MULT_DOSStub_d9b3 {
  strings:
    $key_d9b3 = { 8d db [2] f9 c3 [2] be c1 [2] f9 d0 [2] b7 dc [2] bb d6 [2] ac dd [2] b7 93 [2] 8a }

  condition:
    any of them
}