rule TTP_XOR_MULT_DOSStub_6189 {
  strings:
    $key_6189 = { 35 e1 [2] 41 f9 [2] 06 fb [2] 41 ea [2] 0f e6 [2] 03 ec [2] 14 e7 [2] 0f a9 [2] 32 }

  condition:
    any of them
}