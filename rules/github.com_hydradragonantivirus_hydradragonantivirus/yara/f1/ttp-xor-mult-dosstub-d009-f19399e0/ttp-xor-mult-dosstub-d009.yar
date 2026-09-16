rule TTP_XOR_MULT_DOSStub_d009 {
  strings:
    $key_d009 = { 84 61 [2] f0 79 [2] b7 7b [2] f0 6a [2] be 66 [2] b2 6c [2] a5 67 [2] be 29 [2] 83 }

  condition:
    any of them
}