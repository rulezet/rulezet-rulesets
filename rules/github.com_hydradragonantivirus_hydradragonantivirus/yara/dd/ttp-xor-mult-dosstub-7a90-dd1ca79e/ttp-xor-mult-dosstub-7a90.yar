rule TTP_XOR_MULT_DOSStub_7a90 {
  strings:
    $key_7a90 = { 2e f8 [2] 5a e0 [2] 1d e2 [2] 5a f3 [2] 14 ff [2] 18 f5 [2] 0f fe [2] 14 b0 [2] 29 }

  condition:
    any of them
}