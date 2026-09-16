rule TTP_XOR_MULT_DOSStub_a2c4 {
  strings:
    $key_a2c4 = { f6 ac [2] 82 b4 [2] c5 b6 [2] 82 a7 [2] cc ab [2] c0 a1 [2] d7 aa [2] cc e4 [2] f1 }

  condition:
    any of them
}