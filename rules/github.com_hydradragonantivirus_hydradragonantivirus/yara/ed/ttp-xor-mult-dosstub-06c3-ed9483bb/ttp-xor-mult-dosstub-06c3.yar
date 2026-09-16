rule TTP_XOR_MULT_DOSStub_06c3 {
  strings:
    $key_06c3 = { 52 ab [2] 26 b3 [2] 61 b1 [2] 26 a0 [2] 68 ac [2] 64 a6 [2] 73 ad [2] 68 e3 [2] 55 }

  condition:
    any of them
}