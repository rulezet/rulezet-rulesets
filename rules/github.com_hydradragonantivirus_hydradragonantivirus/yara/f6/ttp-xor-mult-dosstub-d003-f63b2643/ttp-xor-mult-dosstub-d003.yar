rule TTP_XOR_MULT_DOSStub_d003 {
  strings:
    $key_d003 = { 84 6b [2] f0 73 [2] b7 71 [2] f0 60 [2] be 6c [2] b2 66 [2] a5 6d [2] be 23 [2] 83 }

  condition:
    any of them
}