rule TTP_XOR_MULT_DOSStub_64aa {
  strings:
    $key_64aa = { 30 c2 [2] 44 da [2] 03 d8 [2] 44 c9 [2] 0a c5 [2] 06 cf [2] 11 c4 [2] 0a 8a [2] 37 }

  condition:
    any of them
}