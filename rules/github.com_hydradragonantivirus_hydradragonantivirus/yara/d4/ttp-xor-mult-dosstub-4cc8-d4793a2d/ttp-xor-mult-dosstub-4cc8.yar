rule TTP_XOR_MULT_DOSStub_4cc8 {
  strings:
    $key_4cc8 = { 18 a0 [2] 6c b8 [2] 2b ba [2] 6c ab [2] 22 a7 [2] 2e ad [2] 39 a6 [2] 22 e8 [2] 1f }

  condition:
    any of them
}