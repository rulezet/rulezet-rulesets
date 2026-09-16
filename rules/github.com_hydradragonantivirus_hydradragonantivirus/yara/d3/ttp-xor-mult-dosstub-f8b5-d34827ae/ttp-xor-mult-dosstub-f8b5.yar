rule TTP_XOR_MULT_DOSStub_f8b5 {
  strings:
    $key_f8b5 = { ac dd [2] d8 c5 [2] 9f c7 [2] d8 d6 [2] 96 da [2] 9a d0 [2] 8d db [2] 96 95 [2] ab }

  condition:
    any of them
}