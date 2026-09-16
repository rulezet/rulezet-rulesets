rule TTP_XOR_MULT_DOSStub_20c8 {
  strings:
    $key_20c8 = { 74 a0 [2] 00 b8 [2] 47 ba [2] 00 ab [2] 4e a7 [2] 42 ad [2] 55 a6 [2] 4e e8 [2] 73 }

  condition:
    any of them
}