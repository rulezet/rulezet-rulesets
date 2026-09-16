rule TTP_XOR_MULT_DOSStub_6585 {
  strings:
    $key_6585 = { 31 ed [2] 45 f5 [2] 02 f7 [2] 45 e6 [2] 0b ea [2] 07 e0 [2] 10 eb [2] 0b a5 [2] 36 }

  condition:
    any of them
}