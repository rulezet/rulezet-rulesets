rule TTP_XOR_MULT_DOSStub_94bf {
  strings:
    $key_94bf = { c0 d7 [2] b4 cf [2] f3 cd [2] b4 dc [2] fa d0 [2] f6 da [2] e1 d1 [2] fa 9f [2] c7 }

  condition:
    any of them
}