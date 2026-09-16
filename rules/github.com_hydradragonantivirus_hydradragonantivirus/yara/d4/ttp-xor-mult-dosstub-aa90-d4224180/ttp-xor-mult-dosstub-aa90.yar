rule TTP_XOR_MULT_DOSStub_aa90 {
  strings:
    $key_aa90 = { fe f8 [2] 8a e0 [2] cd e2 [2] 8a f3 [2] c4 ff [2] c8 f5 [2] df fe [2] c4 b0 [2] f9 }

  condition:
    any of them
}