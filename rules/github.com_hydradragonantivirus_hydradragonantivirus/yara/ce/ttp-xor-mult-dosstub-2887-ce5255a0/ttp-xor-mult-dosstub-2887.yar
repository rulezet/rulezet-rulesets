rule TTP_XOR_MULT_DOSStub_2887 {
  strings:
    $key_2887 = { 7c ef [2] 08 f7 [2] 4f f5 [2] 08 e4 [2] 46 e8 [2] 4a e2 [2] 5d e9 [2] 46 a7 [2] 7b }

  condition:
    any of them
}