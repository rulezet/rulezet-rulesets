rule TTP_XOR_MULT_DOSStub_d3bf {
  strings:
    $key_d3bf = { 87 d7 [2] f3 cf [2] b4 cd [2] f3 dc [2] bd d0 [2] b1 da [2] a6 d1 [2] bd 9f [2] 80 }

  condition:
    any of them
}