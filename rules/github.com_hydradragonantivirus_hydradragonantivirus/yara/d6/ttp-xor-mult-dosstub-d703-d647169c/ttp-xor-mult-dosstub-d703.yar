rule TTP_XOR_MULT_DOSStub_d703 {
  strings:
    $key_d703 = { 83 6b [2] f7 73 [2] b0 71 [2] f7 60 [2] b9 6c [2] b5 66 [2] a2 6d [2] b9 23 [2] 84 }

  condition:
    any of them
}