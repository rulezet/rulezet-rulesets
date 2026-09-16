rule TTP_XOR_MULT_DOSStub_aacd {
  strings:
    $key_aacd = { fe a5 [2] 8a bd [2] cd bf [2] 8a ae [2] c4 a2 [2] c8 a8 [2] df a3 [2] c4 ed [2] f9 }

  condition:
    any of them
}