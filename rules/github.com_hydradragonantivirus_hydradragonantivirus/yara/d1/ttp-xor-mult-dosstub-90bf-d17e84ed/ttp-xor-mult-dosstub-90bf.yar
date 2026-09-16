rule TTP_XOR_MULT_DOSStub_90bf {
  strings:
    $key_90bf = { c4 d7 [2] b0 cf [2] f7 cd [2] b0 dc [2] fe d0 [2] f2 da [2] e5 d1 [2] fe 9f [2] c3 }

  condition:
    any of them
}