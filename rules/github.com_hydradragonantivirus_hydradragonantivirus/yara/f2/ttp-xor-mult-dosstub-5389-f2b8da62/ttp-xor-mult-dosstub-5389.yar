rule TTP_XOR_MULT_DOSStub_5389 {
  strings:
    $key_5389 = { 07 e1 [2] 73 f9 [2] 34 fb [2] 73 ea [2] 3d e6 [2] 31 ec [2] 26 e7 [2] 3d a9 [2] 00 }

  condition:
    any of them
}