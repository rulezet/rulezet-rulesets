rule TTP_XOR_MULT_DOSStub_f886 {
  strings:
    $key_f886 = { ac ee [2] d8 f6 [2] 9f f4 [2] d8 e5 [2] 96 e9 [2] 9a e3 [2] 8d e8 [2] 96 a6 [2] ab }

  condition:
    any of them
}