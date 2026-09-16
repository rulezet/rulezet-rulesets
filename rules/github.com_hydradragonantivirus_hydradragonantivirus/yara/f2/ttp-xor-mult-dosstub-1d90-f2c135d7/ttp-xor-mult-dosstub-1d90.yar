rule TTP_XOR_MULT_DOSStub_1d90 {
  strings:
    $key_1d90 = { 49 f8 [2] 3d e0 [2] 7a e2 [2] 3d f3 [2] 73 ff [2] 7f f5 [2] 68 fe [2] 73 b0 [2] 4e }

  condition:
    any of them
}