rule TTP_XOR_MULT_DOSStub_aa30 {
  strings:
    $key_aa30 = { fe 58 [2] 8a 40 [2] cd 42 [2] 8a 53 [2] c4 5f [2] c8 55 [2] df 5e [2] c4 10 [2] f9 }

  condition:
    any of them
}