rule TTP_XOR_MULT_DOSStub_d9b7 {
  strings:
    $key_d9b7 = { 8d df [2] f9 c7 [2] be c5 [2] f9 d4 [2] b7 d8 [2] bb d2 [2] ac d9 [2] b7 97 [2] 8a }

  condition:
    any of them
}