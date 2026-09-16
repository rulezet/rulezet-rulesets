rule TTP_XOR_MULT_DOSStub_d7e2 {
  strings:
    $key_d7e2 = { 83 8a [2] f7 92 [2] b0 90 [2] f7 81 [2] b9 8d [2] b5 87 [2] a2 8c [2] b9 c2 [2] 84 }

  condition:
    any of them
}