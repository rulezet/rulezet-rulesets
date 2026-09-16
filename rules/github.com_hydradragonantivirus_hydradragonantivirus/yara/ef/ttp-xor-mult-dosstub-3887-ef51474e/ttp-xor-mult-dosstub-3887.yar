rule TTP_XOR_MULT_DOSStub_3887 {
  strings:
    $key_3887 = { 6c ef [2] 18 f7 [2] 5f f5 [2] 18 e4 [2] 56 e8 [2] 5a e2 [2] 4d e9 [2] 56 a7 [2] 6b }

  condition:
    any of them
}