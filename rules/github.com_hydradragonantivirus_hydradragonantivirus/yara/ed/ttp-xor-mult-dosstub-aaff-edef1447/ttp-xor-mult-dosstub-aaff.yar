rule TTP_XOR_MULT_DOSStub_aaff {
  strings:
    $key_aaff = { fe 97 [2] 8a 8f [2] cd 8d [2] 8a 9c [2] c4 90 [2] c8 9a [2] df 91 [2] c4 df [2] f9 }

  condition:
    any of them
}