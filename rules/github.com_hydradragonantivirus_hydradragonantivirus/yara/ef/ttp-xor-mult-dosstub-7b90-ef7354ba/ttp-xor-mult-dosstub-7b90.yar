rule TTP_XOR_MULT_DOSStub_7b90 {
  strings:
    $key_7b90 = { 2f f8 [2] 5b e0 [2] 1c e2 [2] 5b f3 [2] 15 ff [2] 19 f5 [2] 0e fe [2] 15 b0 [2] 28 }

  condition:
    any of them
}