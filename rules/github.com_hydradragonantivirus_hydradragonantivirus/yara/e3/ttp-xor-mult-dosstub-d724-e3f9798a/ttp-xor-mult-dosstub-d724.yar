rule TTP_XOR_MULT_DOSStub_d724 {
  strings:
    $key_d724 = { 83 4c [2] f7 54 [2] b0 56 [2] f7 47 [2] b9 4b [2] b5 41 [2] a2 4a [2] b9 04 [2] 84 }

  condition:
    any of them
}