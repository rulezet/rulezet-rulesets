rule TTP_XOR_MULT_DOSStub_d779 {
  strings:
    $key_d779 = { 83 11 [2] f7 09 [2] b0 0b [2] f7 1a [2] b9 16 [2] b5 1c [2] a2 17 [2] b9 59 [2] 84 }

  condition:
    any of them
}