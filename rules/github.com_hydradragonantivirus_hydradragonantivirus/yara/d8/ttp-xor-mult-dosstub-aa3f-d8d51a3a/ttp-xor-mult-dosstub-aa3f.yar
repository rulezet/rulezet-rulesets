rule TTP_XOR_MULT_DOSStub_aa3f {
  strings:
    $key_aa3f = { fe 57 [2] 8a 4f [2] cd 4d [2] 8a 5c [2] c4 50 [2] c8 5a [2] df 51 [2] c4 1f [2] f9 }

  condition:
    any of them
}