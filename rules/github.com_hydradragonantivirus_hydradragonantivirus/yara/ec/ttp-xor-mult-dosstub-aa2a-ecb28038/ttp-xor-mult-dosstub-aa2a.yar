rule TTP_XOR_MULT_DOSStub_aa2a {
  strings:
    $key_aa2a = { fe 42 [2] 8a 5a [2] cd 58 [2] 8a 49 [2] c4 45 [2] c8 4f [2] df 44 [2] c4 0a [2] f9 }

  condition:
    any of them
}