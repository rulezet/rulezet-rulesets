rule TTP_XOR_MULT_DOSStub_83a8 {
  strings:
    $key_83a8 = { d7 c0 [2] a3 d8 [2] e4 da [2] a3 cb [2] ed c7 [2] e1 cd [2] f6 c6 [2] ed 88 [2] d0 }

  condition:
    any of them
}