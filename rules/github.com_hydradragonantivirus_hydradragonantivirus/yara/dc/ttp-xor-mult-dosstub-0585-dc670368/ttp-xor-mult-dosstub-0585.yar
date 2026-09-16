rule TTP_XOR_MULT_DOSStub_0585 {
  strings:
    $key_0585 = { 51 ed [2] 25 f5 [2] 62 f7 [2] 25 e6 [2] 6b ea [2] 67 e0 [2] 70 eb [2] 6b a5 [2] 56 }

  condition:
    any of them
}