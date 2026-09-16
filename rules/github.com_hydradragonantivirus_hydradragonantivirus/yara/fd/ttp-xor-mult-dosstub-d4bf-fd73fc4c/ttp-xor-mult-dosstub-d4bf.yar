rule TTP_XOR_MULT_DOSStub_d4bf {
  strings:
    $key_d4bf = { 80 d7 [2] f4 cf [2] b3 cd [2] f4 dc [2] ba d0 [2] b6 da [2] a1 d1 [2] ba 9f [2] 87 }

  condition:
    any of them
}