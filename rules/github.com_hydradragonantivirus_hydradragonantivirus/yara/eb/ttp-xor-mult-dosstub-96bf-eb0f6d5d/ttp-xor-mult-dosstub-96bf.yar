rule TTP_XOR_MULT_DOSStub_96bf {
  strings:
    $key_96bf = { c2 d7 [2] b6 cf [2] f1 cd [2] b6 dc [2] f8 d0 [2] f4 da [2] e3 d1 [2] f8 9f [2] c5 }

  condition:
    any of them
}