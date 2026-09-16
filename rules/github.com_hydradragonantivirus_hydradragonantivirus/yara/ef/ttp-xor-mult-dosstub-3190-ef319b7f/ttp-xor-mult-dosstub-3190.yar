rule TTP_XOR_MULT_DOSStub_3190 {
  strings:
    $key_3190 = { 65 f8 [2] 11 e0 [2] 56 e2 [2] 11 f3 [2] 5f ff [2] 53 f5 [2] 44 fe [2] 5f b0 [2] 62 }

  condition:
    any of them
}