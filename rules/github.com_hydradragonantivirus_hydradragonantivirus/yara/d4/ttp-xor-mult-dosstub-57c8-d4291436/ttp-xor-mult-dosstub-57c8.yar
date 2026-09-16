rule TTP_XOR_MULT_DOSStub_57c8 {
  strings:
    $key_57c8 = { 03 a0 [2] 77 b8 [2] 30 ba [2] 77 ab [2] 39 a7 [2] 35 ad [2] 22 a6 [2] 39 e8 [2] 04 }

  condition:
    any of them
}