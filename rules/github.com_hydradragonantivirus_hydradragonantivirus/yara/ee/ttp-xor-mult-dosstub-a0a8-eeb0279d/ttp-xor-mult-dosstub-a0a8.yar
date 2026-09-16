rule TTP_XOR_MULT_DOSStub_a0a8 {
  strings:
    $key_a0a8 = { f4 c0 [2] 80 d8 [2] c7 da [2] 80 cb [2] ce c7 [2] c2 cd [2] d5 c6 [2] ce 88 [2] f3 }

  condition:
    any of them
}