rule TTP_XOR_MULT_DOSStub_2590 {
  strings:
    $key_2590 = { 71 f8 [2] 05 e0 [2] 42 e2 [2] 05 f3 [2] 4b ff [2] 47 f5 [2] 50 fe [2] 4b b0 [2] 76 }

  condition:
    any of them
}