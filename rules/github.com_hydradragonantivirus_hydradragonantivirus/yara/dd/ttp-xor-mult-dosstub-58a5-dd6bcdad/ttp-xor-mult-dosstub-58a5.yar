rule TTP_XOR_MULT_DOSStub_58a5 {
  strings:
    $key_58a5 = { 0c cd [2] 78 d5 [2] 3f d7 [2] 78 c6 [2] 36 ca [2] 3a c0 [2] 2d cb [2] 36 85 [2] 0b }

  condition:
    any of them
}