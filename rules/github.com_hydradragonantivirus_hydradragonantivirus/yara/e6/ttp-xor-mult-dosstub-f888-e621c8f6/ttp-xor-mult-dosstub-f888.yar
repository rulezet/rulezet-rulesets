rule TTP_XOR_MULT_DOSStub_f888 {
  strings:
    $key_f888 = { ac e0 [2] d8 f8 [2] 9f fa [2] d8 eb [2] 96 e7 [2] 9a ed [2] 8d e6 [2] 96 a8 [2] ab }

  condition:
    any of them
}