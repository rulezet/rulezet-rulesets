rule TTP_XOR_MULT_DOSStub_d714 {
  strings:
    $key_d714 = { 83 7c [2] f7 64 [2] b0 66 [2] f7 77 [2] b9 7b [2] b5 71 [2] a2 7a [2] b9 34 [2] 84 }

  condition:
    any of them
}