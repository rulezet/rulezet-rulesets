rule TTP_XOR_MULT_DOSStub_5bc8 {
  strings:
    $key_5bc8 = { 0f a0 [2] 7b b8 [2] 3c ba [2] 7b ab [2] 35 a7 [2] 39 ad [2] 2e a6 [2] 35 e8 [2] 08 }

  condition:
    any of them
}