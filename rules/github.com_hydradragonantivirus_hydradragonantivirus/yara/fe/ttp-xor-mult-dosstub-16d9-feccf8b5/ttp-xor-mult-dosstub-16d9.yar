rule TTP_XOR_MULT_DOSStub_16d9 {
  strings:
    $key_16d9 = { 42 b1 [2] 36 a9 [2] 71 ab [2] 36 ba [2] 78 b6 [2] 74 bc [2] 63 b7 [2] 78 f9 [2] 45 }

  condition:
    any of them
}