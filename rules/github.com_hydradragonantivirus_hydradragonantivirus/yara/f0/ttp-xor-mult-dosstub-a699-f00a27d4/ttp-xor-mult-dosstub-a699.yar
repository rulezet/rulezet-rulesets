rule TTP_XOR_MULT_DOSStub_a699 {
  strings:
    $key_a699 = { f2 f1 [2] 86 e9 [2] c1 eb [2] 86 fa [2] c8 f6 [2] c4 fc [2] d3 f7 [2] c8 b9 [2] f5 }

  condition:
    any of them
}