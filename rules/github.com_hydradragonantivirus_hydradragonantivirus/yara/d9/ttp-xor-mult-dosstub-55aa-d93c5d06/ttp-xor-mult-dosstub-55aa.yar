rule TTP_XOR_MULT_DOSStub_55aa {
  strings:
    $key_55aa = { 01 c2 [2] 75 da [2] 32 d8 [2] 75 c9 [2] 3b c5 [2] 37 cf [2] 20 c4 [2] 3b 8a [2] 06 }

  condition:
    any of them
}