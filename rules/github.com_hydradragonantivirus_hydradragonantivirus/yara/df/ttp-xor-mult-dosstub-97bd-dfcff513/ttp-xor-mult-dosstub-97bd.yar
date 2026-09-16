rule TTP_XOR_MULT_DOSStub_97bd {
  strings:
    $key_97bd = { c3 d5 [2] b7 cd [2] f0 cf [2] b7 de [2] f9 d2 [2] f5 d8 [2] e2 d3 [2] f9 9d [2] c4 }

  condition:
    any of them
}