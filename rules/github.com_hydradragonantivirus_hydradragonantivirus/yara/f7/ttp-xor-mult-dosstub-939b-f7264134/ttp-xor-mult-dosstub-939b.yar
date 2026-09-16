rule TTP_XOR_MULT_DOSStub_939b {
  strings:
    $key_939b = { c7 f3 [2] b3 eb [2] f4 e9 [2] b3 f8 [2] fd f4 [2] f1 fe [2] e6 f5 [2] fd bb [2] c0 }

  condition:
    any of them
}