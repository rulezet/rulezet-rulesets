rule TTP_XOR_MULT_DOSStub_d674 {
  strings:
    $key_d674 = { 82 1c [2] f6 04 [2] b1 06 [2] f6 17 [2] b8 1b [2] b4 11 [2] a3 1a [2] b8 54 [2] 85 }

  condition:
    any of them
}