rule TTP_XOR_MULT_DOSStub_d7bd {
  strings:
    $key_d7bd = { 83 d5 [2] f7 cd [2] b0 cf [2] f7 de [2] b9 d2 [2] b5 d8 [2] a2 d3 [2] b9 9d [2] 84 }

  condition:
    any of them
}