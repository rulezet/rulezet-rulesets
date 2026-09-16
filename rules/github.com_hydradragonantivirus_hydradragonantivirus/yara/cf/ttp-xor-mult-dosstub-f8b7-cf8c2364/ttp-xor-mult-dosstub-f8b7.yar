rule TTP_XOR_MULT_DOSStub_f8b7 {
  strings:
    $key_f8b7 = { ac df [2] d8 c7 [2] 9f c5 [2] d8 d4 [2] 96 d8 [2] 9a d2 [2] 8d d9 [2] 96 97 [2] ab }

  condition:
    any of them
}