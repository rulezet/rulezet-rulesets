rule TTP_XOR_MULT_DOSStub_ea88 {
  strings:
    $key_ea88 = { be e0 [2] ca f8 [2] 8d fa [2] ca eb [2] 84 e7 [2] 88 ed [2] 9f e6 [2] 84 a8 [2] b9 }

  condition:
    any of them
}