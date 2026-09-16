rule TTP_XOR_MULT_DOSStub_26aa {
  strings:
    $key_26aa = { 72 c2 [2] 06 da [2] 41 d8 [2] 06 c9 [2] 48 c5 [2] 44 cf [2] 53 c4 [2] 48 8a [2] 75 }

  condition:
    any of them
}