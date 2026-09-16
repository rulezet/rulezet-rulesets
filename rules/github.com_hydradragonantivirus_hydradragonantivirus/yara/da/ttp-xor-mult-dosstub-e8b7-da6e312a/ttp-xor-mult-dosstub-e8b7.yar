rule TTP_XOR_MULT_DOSStub_e8b7 {
  strings:
    $key_e8b7 = { bc df [2] c8 c7 [2] 8f c5 [2] c8 d4 [2] 86 d8 [2] 8a d2 [2] 9d d9 [2] 86 97 [2] bb }

  condition:
    any of them
}