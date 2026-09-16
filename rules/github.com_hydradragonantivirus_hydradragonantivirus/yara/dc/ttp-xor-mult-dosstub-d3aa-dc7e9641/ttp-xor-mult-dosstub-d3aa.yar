rule TTP_XOR_MULT_DOSStub_d3aa {
  strings:
    $key_d3aa = { 87 c2 [2] f3 da [2] b4 d8 [2] f3 c9 [2] bd c5 [2] b1 cf [2] a6 c4 [2] bd 8a [2] 80 }

  condition:
    any of them
}