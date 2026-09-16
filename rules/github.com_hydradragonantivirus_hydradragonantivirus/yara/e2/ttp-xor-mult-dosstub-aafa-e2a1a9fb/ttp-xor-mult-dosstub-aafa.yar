rule TTP_XOR_MULT_DOSStub_aafa {
  strings:
    $key_aafa = { fe 92 [2] 8a 8a [2] cd 88 [2] 8a 99 [2] c4 95 [2] c8 9f [2] df 94 [2] c4 da [2] f9 }

  condition:
    any of them
}