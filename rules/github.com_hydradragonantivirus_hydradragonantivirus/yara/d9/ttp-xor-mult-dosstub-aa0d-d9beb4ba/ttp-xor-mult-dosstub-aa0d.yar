rule TTP_XOR_MULT_DOSStub_aa0d {
  strings:
    $key_aa0d = { fe 65 [2] 8a 7d [2] cd 7f [2] 8a 6e [2] c4 62 [2] c8 68 [2] df 63 [2] c4 2d [2] f9 }

  condition:
    any of them
}