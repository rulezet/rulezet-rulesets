rule TTP_XOR_MULT_DOSStub_aa21 {
  strings:
    $key_aa21 = { fe 49 [2] 8a 51 [2] cd 53 [2] 8a 42 [2] c4 4e [2] c8 44 [2] df 4f [2] c4 01 [2] f9 }

  condition:
    any of them
}