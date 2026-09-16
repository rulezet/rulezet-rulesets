rule TTP_XOR_MULT_DOSStub_44c5 {
  strings:
    $key_44c5 = { 10 ad [2] 64 b5 [2] 23 b7 [2] 64 a6 [2] 2a aa [2] 26 a0 [2] 31 ab [2] 2a e5 [2] 17 }

  condition:
    any of them
}