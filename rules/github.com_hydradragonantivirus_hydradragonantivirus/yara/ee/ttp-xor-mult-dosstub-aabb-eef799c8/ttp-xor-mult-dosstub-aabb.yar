rule TTP_XOR_MULT_DOSStub_aabb {
  strings:
    $key_aabb = { fe d3 [2] 8a cb [2] cd c9 [2] 8a d8 [2] c4 d4 [2] c8 de [2] df d5 [2] c4 9b [2] f9 }

  condition:
    any of them
}