rule TTP_XOR_MULT_DOSStub_8685 {
  strings:
    $key_8685 = { d2 ed [2] a6 f5 [2] e1 f7 [2] a6 e6 [2] e8 ea [2] e4 e0 [2] f3 eb [2] e8 a5 [2] d5 }

  condition:
    any of them
}