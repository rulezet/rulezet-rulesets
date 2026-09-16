rule TTP_XOR_MULT_DOSStub_4cc5 {
  strings:
    $key_4cc5 = { 18 ad [2] 6c b5 [2] 2b b7 [2] 6c a6 [2] 22 aa [2] 2e a0 [2] 39 ab [2] 22 e5 [2] 1f }

  condition:
    any of them
}