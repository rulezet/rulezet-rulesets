rule TTP_XOR_MULT_DOSStub_5190 {
  strings:
    $key_5190 = { 05 f8 [2] 71 e0 [2] 36 e2 [2] 71 f3 [2] 3f ff [2] 33 f5 [2] 24 fe [2] 3f b0 [2] 02 }

  condition:
    any of them
}