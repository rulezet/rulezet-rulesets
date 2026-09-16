rule TTP_XOR_MULT_DOSStub_a4a8 {
  strings:
    $key_a4a8 = { f0 c0 [2] 84 d8 [2] c3 da [2] 84 cb [2] ca c7 [2] c6 cd [2] d1 c6 [2] ca 88 [2] f7 }

  condition:
    any of them
}