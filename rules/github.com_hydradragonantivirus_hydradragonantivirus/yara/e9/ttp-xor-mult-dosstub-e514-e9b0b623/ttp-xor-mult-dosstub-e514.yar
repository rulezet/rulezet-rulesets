rule TTP_XOR_MULT_DOSStub_e514 {
  strings:
    $key_e514 = { b1 7c [2] c5 64 [2] 82 66 [2] c5 77 [2] 8b 7b [2] 87 71 [2] 90 7a [2] 8b 34 [2] b6 }

  condition:
    any of them
}