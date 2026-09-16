rule TTP_XOR_MULT_DOSStub_5d91 {
  strings:
    $key_5d91 = { 09 f9 [2] 7d e1 [2] 3a e3 [2] 7d f2 [2] 33 fe [2] 3f f4 [2] 28 ff [2] 33 b1 [2] 0e }

  condition:
    any of them
}