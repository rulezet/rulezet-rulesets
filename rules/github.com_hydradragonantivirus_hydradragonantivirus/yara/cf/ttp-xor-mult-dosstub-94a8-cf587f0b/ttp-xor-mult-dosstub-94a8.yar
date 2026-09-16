rule TTP_XOR_MULT_DOSStub_94a8 {
  strings:
    $key_94a8 = { c0 c0 [2] b4 d8 [2] f3 da [2] b4 cb [2] fa c7 [2] f6 cd [2] e1 c6 [2] fa 88 [2] c7 }

  condition:
    any of them
}