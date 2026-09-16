rule TTP_XOR_MULT_DOSStub_a2c6 {
  strings:
    $key_a2c6 = { f6 ae [2] 82 b6 [2] c5 b4 [2] 82 a5 [2] cc a9 [2] c0 a3 [2] d7 a8 [2] cc e6 [2] f1 }

  condition:
    any of them
}