rule TTP_XOR_MULT_DOSStub_21aa {
  strings:
    $key_21aa = { 75 c2 [2] 01 da [2] 46 d8 [2] 01 c9 [2] 4f c5 [2] 43 cf [2] 54 c4 [2] 4f 8a [2] 72 }

  condition:
    any of them
}