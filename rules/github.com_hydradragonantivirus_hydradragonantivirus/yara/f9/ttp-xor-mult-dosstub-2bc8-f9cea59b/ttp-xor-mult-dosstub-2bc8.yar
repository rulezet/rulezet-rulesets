rule TTP_XOR_MULT_DOSStub_2bc8 {
  strings:
    $key_2bc8 = { 7f a0 [2] 0b b8 [2] 4c ba [2] 0b ab [2] 45 a7 [2] 49 ad [2] 5e a6 [2] 45 e8 [2] 78 }

  condition:
    any of them
}