rule TTP_XOR_MULT_DOSStub_41aa {
  strings:
    $key_41aa = { 15 c2 [2] 61 da [2] 26 d8 [2] 61 c9 [2] 2f c5 [2] 23 cf [2] 34 c4 [2] 2f 8a [2] 12 }

  condition:
    any of them
}