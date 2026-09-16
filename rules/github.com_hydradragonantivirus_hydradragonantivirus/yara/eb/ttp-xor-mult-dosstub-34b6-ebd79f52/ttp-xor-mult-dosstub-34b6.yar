rule TTP_XOR_MULT_DOSStub_34b6 {
  strings:
    $key_34b6 = { 60 de [2] 14 c6 [2] 53 c4 [2] 14 d5 [2] 5a d9 [2] 56 d3 [2] 41 d8 [2] 5a 96 [2] 67 }

  condition:
    any of them
}