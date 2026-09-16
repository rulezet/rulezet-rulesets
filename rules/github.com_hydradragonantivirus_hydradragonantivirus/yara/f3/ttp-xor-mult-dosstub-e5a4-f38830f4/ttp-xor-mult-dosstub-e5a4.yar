rule TTP_XOR_MULT_DOSStub_e5a4 {
  strings:
    $key_e5a4 = { b1 cc [2] c5 d4 [2] 82 d6 [2] c5 c7 [2] 8b cb [2] 87 c1 [2] 90 ca [2] 8b 84 [2] b6 }

  condition:
    any of them
}