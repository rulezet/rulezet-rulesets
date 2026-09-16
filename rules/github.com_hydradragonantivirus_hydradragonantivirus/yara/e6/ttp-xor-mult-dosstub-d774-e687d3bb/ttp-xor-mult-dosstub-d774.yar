rule TTP_XOR_MULT_DOSStub_d774 {
  strings:
    $key_d774 = { 83 1c [2] f7 04 [2] b0 06 [2] f7 17 [2] b9 1b [2] b5 11 [2] a2 1a [2] b9 54 [2] 84 }

  condition:
    any of them
}