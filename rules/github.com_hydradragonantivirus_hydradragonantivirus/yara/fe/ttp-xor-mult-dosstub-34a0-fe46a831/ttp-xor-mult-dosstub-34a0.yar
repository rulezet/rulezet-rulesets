rule TTP_XOR_MULT_DOSStub_34a0 {
  strings:
    $key_34a0 = { 60 c8 [2] 14 d0 [2] 53 d2 [2] 14 c3 [2] 5a cf [2] 56 c5 [2] 41 ce [2] 5a 80 [2] 67 }

  condition:
    any of them
}