rule TTP_XOR_MULT_DOSStub_7cc8 {
  strings:
    $key_7cc8 = { 28 a0 [2] 5c b8 [2] 1b ba [2] 5c ab [2] 12 a7 [2] 1e ad [2] 09 a6 [2] 12 e8 [2] 2f }

  condition:
    any of them
}