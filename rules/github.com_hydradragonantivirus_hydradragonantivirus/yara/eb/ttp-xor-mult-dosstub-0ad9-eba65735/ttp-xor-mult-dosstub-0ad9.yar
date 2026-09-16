rule TTP_XOR_MULT_DOSStub_0ad9 {
  strings:
    $key_0ad9 = { 5e b1 [2] 2a a9 [2] 6d ab [2] 2a ba [2] 64 b6 [2] 68 bc [2] 7f b7 [2] 64 f9 [2] 59 }

  condition:
    any of them
}