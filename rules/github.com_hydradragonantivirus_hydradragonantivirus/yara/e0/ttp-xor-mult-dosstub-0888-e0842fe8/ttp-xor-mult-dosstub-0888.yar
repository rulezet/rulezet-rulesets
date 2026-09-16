rule TTP_XOR_MULT_DOSStub_0888 {
  strings:
    $key_0888 = { 5c e0 [2] 28 f8 [2] 6f fa [2] 28 eb [2] 66 e7 [2] 6a ed [2] 7d e6 [2] 66 a8 [2] 5b }

  condition:
    any of them
}