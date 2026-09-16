rule TTP_XOR_MULT_DOSStub_4ac5 {
  strings:
    $key_4ac5 = { 1e ad [2] 6a b5 [2] 2d b7 [2] 6a a6 [2] 24 aa [2] 28 a0 [2] 3f ab [2] 24 e5 [2] 19 }

  condition:
    any of them
}