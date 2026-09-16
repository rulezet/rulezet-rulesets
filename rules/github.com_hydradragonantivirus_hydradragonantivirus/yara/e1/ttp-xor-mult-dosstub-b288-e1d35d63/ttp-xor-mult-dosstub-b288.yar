rule TTP_XOR_MULT_DOSStub_b288 {
  strings:
    $key_b288 = { e6 e0 [2] 92 f8 [2] d5 fa [2] 92 eb [2] dc e7 [2] d0 ed [2] c7 e6 [2] dc a8 [2] e1 }

  condition:
    any of them
}