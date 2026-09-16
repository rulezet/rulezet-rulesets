rule TTP_XOR_MULT_DOSStub_34a7 {
  strings:
    $key_34a7 = { 60 cf [2] 14 d7 [2] 53 d5 [2] 14 c4 [2] 5a c8 [2] 56 c2 [2] 41 c9 [2] 5a 87 [2] 67 }

  condition:
    any of them
}