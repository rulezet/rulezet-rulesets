rule TTP_XOR_MULT_DOSStub_d0bf {
  strings:
    $key_d0bf = { 84 d7 [2] f0 cf [2] b7 cd [2] f0 dc [2] be d0 [2] b2 da [2] a5 d1 [2] be 9f [2] 83 }

  condition:
    any of them
}