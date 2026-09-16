rule TTP_XOR_MULT_DOSStub_f883 {
  strings:
    $key_f883 = { ac eb [2] d8 f3 [2] 9f f1 [2] d8 e0 [2] 96 ec [2] 9a e6 [2] 8d ed [2] 96 a3 [2] ab }

  condition:
    any of them
}