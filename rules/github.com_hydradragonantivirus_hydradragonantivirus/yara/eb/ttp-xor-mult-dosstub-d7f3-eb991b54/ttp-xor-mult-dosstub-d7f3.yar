rule TTP_XOR_MULT_DOSStub_d7f3 {
  strings:
    $key_d7f3 = { 83 9b [2] f7 83 [2] b0 81 [2] f7 90 [2] b9 9c [2] b5 96 [2] a2 9d [2] b9 d3 [2] 84 }

  condition:
    any of them
}