rule TTP_XOR_MULT_DOSStub_a7a8 {
  strings:
    $key_a7a8 = { f3 c0 [2] 87 d8 [2] c0 da [2] 87 cb [2] c9 c7 [2] c5 cd [2] d2 c6 [2] c9 88 [2] f4 }

  condition:
    any of them
}