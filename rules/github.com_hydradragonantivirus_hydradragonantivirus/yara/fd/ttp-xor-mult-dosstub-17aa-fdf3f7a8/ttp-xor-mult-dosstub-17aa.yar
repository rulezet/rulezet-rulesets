rule TTP_XOR_MULT_DOSStub_17aa {
  strings:
    $key_17aa = { 43 c2 [2] 37 da [2] 70 d8 [2] 37 c9 [2] 79 c5 [2] 75 cf [2] 62 c4 [2] 79 8a [2] 44 }

  condition:
    any of them
}