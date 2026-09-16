rule TTP_XOR_MULT_DOSStub_a188 {
  strings:
    $key_a188 = { f5 e0 [2] 81 f8 [2] c6 fa [2] 81 eb [2] cf e7 [2] c3 ed [2] d4 e6 [2] cf a8 [2] f2 }

  condition:
    any of them
}