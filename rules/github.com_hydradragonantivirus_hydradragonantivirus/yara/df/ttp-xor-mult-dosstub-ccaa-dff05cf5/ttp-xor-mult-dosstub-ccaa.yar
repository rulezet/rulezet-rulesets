rule TTP_XOR_MULT_DOSStub_ccaa {
  strings:
    $key_ccaa = { 98 c2 [2] ec da [2] ab d8 [2] ec c9 [2] a2 c5 [2] ae cf [2] b9 c4 [2] a2 8a [2] 9f }

  condition:
    any of them
}