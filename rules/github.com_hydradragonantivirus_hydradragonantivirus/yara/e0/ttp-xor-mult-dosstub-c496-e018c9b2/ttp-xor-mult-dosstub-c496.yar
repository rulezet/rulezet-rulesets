rule TTP_XOR_MULT_DOSStub_c496 {
  strings:
    $key_c496 = { 90 fe [2] e4 e6 [2] a3 e4 [2] e4 f5 [2] aa f9 [2] a6 f3 [2] b1 f8 [2] aa b6 [2] 97 }

  condition:
    any of them
}