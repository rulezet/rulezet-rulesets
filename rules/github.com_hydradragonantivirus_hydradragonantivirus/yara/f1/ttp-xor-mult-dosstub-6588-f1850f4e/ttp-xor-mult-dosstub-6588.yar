rule TTP_XOR_MULT_DOSStub_6588 {
  strings:
    $key_6588 = { 31 e0 [2] 45 f8 [2] 02 fa [2] 45 eb [2] 0b e7 [2] 07 ed [2] 10 e6 [2] 0b a8 [2] 36 }

  condition:
    any of them
}