rule TTP_XOR_MULT_DOSStub_33aa {
  strings:
    $key_33aa = { 67 c2 [2] 13 da [2] 54 d8 [2] 13 c9 [2] 5d c5 [2] 51 cf [2] 46 c4 [2] 5d 8a [2] 60 }

  condition:
    any of them
}