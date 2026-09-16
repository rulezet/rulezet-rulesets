rule TTP_XOR_MULT_DOSStub_bba5 {
  strings:
    $key_bba5 = { ef cd [2] 9b d5 [2] dc d7 [2] 9b c6 [2] d5 ca [2] d9 c0 [2] ce cb [2] d5 85 [2] e8 }

  condition:
    any of them
}