rule TTP_XOR_MULT_DOSStub_5d90 {
  strings:
    $key_5d90 = { 09 f8 [2] 7d e0 [2] 3a e2 [2] 7d f3 [2] 33 ff [2] 3f f5 [2] 28 fe [2] 33 b0 [2] 0e }

  condition:
    any of them
}