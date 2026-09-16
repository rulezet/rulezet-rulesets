rule TTP_XOR_MULT_DOSStub_5fb7 {
  strings:
    $key_5fb7 = { 0b df [2] 7f c7 [2] 38 c5 [2] 7f d4 [2] 31 d8 [2] 3d d2 [2] 2a d9 [2] 31 97 [2] 0c }

  condition:
    any of them
}