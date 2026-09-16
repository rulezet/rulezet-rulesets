rule TTP_XOR_MULT_DOSStub_aacc {
  strings:
    $key_aacc = { fe a4 [2] 8a bc [2] cd be [2] 8a af [2] c4 a3 [2] c8 a9 [2] df a2 [2] c4 ec [2] f9 }

  condition:
    any of them
}