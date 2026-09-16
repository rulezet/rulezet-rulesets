rule TTP_XOR_MULT_DOSStub_13aa {
  strings:
    $key_13aa = { 47 c2 [2] 33 da [2] 74 d8 [2] 33 c9 [2] 7d c5 [2] 71 cf [2] 66 c4 [2] 7d 8a [2] 40 }

  condition:
    any of them
}