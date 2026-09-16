rule TTP_XOR_MULT_DOSStub_d7e9 {
  strings:
    $key_d7e9 = { 83 81 [2] f7 99 [2] b0 9b [2] f7 8a [2] b9 86 [2] b5 8c [2] a2 87 [2] b9 c9 [2] 84 }

  condition:
    any of them
}