rule TTP_XOR_MULT_DOSStub_aa1c {
  strings:
    $key_aa1c = { fe 74 [2] 8a 6c [2] cd 6e [2] 8a 7f [2] c4 73 [2] c8 79 [2] df 72 [2] c4 3c [2] f9 }

  condition:
    any of them
}