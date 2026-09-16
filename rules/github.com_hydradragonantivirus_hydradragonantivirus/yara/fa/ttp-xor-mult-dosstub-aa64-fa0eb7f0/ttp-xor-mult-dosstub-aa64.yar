rule TTP_XOR_MULT_DOSStub_aa64 {
  strings:
    $key_aa64 = { fe 0c [2] 8a 14 [2] cd 16 [2] 8a 07 [2] c4 0b [2] c8 01 [2] df 0a [2] c4 44 [2] f9 }

  condition:
    any of them
}