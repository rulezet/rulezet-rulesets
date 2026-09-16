rule TTP_XOR_MULT_DOSStub_d6e9 {
  strings:
    $key_d6e9 = { 82 81 [2] f6 99 [2] b1 9b [2] f6 8a [2] b8 86 [2] b4 8c [2] a3 87 [2] b8 c9 [2] 85 }

  condition:
    any of them
}