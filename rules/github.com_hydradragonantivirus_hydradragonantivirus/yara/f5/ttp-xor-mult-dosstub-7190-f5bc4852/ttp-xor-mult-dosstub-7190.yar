rule TTP_XOR_MULT_DOSStub_7190 {
  strings:
    $key_7190 = { 25 f8 [2] 51 e0 [2] 16 e2 [2] 51 f3 [2] 1f ff [2] 13 f5 [2] 04 fe [2] 1f b0 [2] 22 }

  condition:
    any of them
}