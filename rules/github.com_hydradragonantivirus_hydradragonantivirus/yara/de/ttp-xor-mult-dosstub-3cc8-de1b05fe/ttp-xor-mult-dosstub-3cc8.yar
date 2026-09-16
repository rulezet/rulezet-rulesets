rule TTP_XOR_MULT_DOSStub_3cc8 {
  strings:
    $key_3cc8 = { 68 a0 [2] 1c b8 [2] 5b ba [2] 1c ab [2] 52 a7 [2] 5e ad [2] 49 a6 [2] 52 e8 [2] 6f }

  condition:
    any of them
}