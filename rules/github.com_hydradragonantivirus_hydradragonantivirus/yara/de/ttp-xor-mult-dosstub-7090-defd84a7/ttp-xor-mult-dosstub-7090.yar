rule TTP_XOR_MULT_DOSStub_7090 {
  strings:
    $key_7090 = { 24 f8 [2] 50 e0 [2] 17 e2 [2] 50 f3 [2] 1e ff [2] 12 f5 [2] 05 fe [2] 1e b0 [2] 23 }

  condition:
    any of them
}