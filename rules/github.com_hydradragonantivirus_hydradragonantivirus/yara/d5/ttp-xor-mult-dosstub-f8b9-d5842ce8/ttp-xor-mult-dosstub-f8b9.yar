rule TTP_XOR_MULT_DOSStub_f8b9 {
  strings:
    $key_f8b9 = { ac d1 [2] d8 c9 [2] 9f cb [2] d8 da [2] 96 d6 [2] 9a dc [2] 8d d7 [2] 96 99 [2] ab }

  condition:
    any of them
}