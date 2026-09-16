rule TTP_XOR_MULT_DOSStub_d7bf {
  strings:
    $key_d7bf = { 83 d7 [2] f7 cf [2] b0 cd [2] f7 dc [2] b9 d0 [2] b5 da [2] a2 d1 [2] b9 9f [2] 84 }

  condition:
    any of them
}