rule TTP_XOR_MULT_DOSStub_94a5 {
  strings:
    $key_94a5 = { c0 cd [2] b4 d5 [2] f3 d7 [2] b4 c6 [2] fa ca [2] f6 c0 [2] e1 cb [2] fa 85 [2] c7 }

  condition:
    any of them
}