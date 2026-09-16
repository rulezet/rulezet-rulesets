rule TTP_XOR_MULT_DOSStub_93a7 {
  strings:
    $key_93a7 = { c7 cf [2] b3 d7 [2] f4 d5 [2] b3 c4 [2] fd c8 [2] f1 c2 [2] e6 c9 [2] fd 87 [2] c0 }

  condition:
    any of them
}