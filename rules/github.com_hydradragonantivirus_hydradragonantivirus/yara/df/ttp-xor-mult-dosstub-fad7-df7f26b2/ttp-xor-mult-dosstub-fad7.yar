rule TTP_XOR_MULT_DOSStub_fad7 {
  strings:
    $key_fad7 = { ae bf [2] da a7 [2] 9d a5 [2] da b4 [2] 94 b8 [2] 98 b2 [2] 8f b9 [2] 94 f7 [2] a9 }

  condition:
    any of them
}