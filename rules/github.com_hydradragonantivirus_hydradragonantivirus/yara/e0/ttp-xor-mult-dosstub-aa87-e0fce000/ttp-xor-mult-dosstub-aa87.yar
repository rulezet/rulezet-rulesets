rule TTP_XOR_MULT_DOSStub_aa87 {
  strings:
    $key_aa87 = { fe ef [2] 8a f7 [2] cd f5 [2] 8a e4 [2] c4 e8 [2] c8 e2 [2] df e9 [2] c4 a7 [2] f9 }

  condition:
    any of them
}