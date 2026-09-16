rule TTP_XOR_MULT_DOSStub_3fb7 {
  strings:
    $key_3fb7 = { 6b df [2] 1f c7 [2] 58 c5 [2] 1f d4 [2] 51 d8 [2] 5d d2 [2] 4a d9 [2] 51 97 [2] 6c }

  condition:
    any of them
}