rule TTP_XOR_MULT_DOSStub_0190 {
  strings:
    $key_0190 = { 55 f8 [2] 21 e0 [2] 66 e2 [2] 21 f3 [2] 6f ff [2] 63 f5 [2] 74 fe [2] 6f b0 [2] 52 }

  condition:
    any of them
}