rule TTP_XOR_MULT_DOSStub_6190 {
  strings:
    $key_6190 = { 35 f8 [2] 41 e0 [2] 06 e2 [2] 41 f3 [2] 0f ff [2] 03 f5 [2] 14 fe [2] 0f b0 [2] 32 }

  condition:
    any of them
}