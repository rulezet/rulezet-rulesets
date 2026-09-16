rule TTP_XOR_MULT_DOSStub_f8b4 {
  strings:
    $key_f8b4 = { ac dc [2] d8 c4 [2] 9f c6 [2] d8 d7 [2] 96 db [2] 9a d1 [2] 8d da [2] 96 94 [2] ab }

  condition:
    any of them
}