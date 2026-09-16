rule TTP_XOR_MULT_DOSStub_24c8 {
  strings:
    $key_24c8 = { 70 a0 [2] 04 b8 [2] 43 ba [2] 04 ab [2] 4a a7 [2] 46 ad [2] 51 a6 [2] 4a e8 [2] 77 }

  condition:
    any of them
}