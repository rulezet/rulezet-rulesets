rule TTP_XOR_MULT_DOSStub_aaca {
  strings:
    $key_aaca = { fe a2 [2] 8a ba [2] cd b8 [2] 8a a9 [2] c4 a5 [2] c8 af [2] df a4 [2] c4 ea [2] f9 }

  condition:
    any of them
}