rule TTP_XOR_MULT_DOSStub_0988 {
  strings:
    $key_0988 = { 5d e0 [2] 29 f8 [2] 6e fa [2] 29 eb [2] 67 e7 [2] 6b ed [2] 7c e6 [2] 67 a8 [2] 5a }

  condition:
    any of them
}