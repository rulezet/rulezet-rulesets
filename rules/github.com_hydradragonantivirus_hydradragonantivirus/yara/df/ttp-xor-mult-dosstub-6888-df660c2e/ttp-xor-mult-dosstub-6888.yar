rule TTP_XOR_MULT_DOSStub_6888 {
  strings:
    $key_6888 = { 3c e0 [2] 48 f8 [2] 0f fa [2] 48 eb [2] 06 e7 [2] 0a ed [2] 1d e6 [2] 06 a8 [2] 3b }

  condition:
    any of them
}