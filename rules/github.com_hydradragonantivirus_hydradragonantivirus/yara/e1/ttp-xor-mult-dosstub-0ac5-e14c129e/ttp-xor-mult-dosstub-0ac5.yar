rule TTP_XOR_MULT_DOSStub_0ac5 {
  strings:
    $key_0ac5 = { 5e ad [2] 2a b5 [2] 6d b7 [2] 2a a6 [2] 64 aa [2] 68 a0 [2] 7f ab [2] 64 e5 [2] 59 }

  condition:
    any of them
}