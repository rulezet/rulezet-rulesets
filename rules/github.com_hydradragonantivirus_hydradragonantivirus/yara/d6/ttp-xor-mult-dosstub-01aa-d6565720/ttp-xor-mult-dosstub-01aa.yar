rule TTP_XOR_MULT_DOSStub_01aa {
  strings:
    $key_01aa = { 55 c2 [2] 21 da [2] 66 d8 [2] 21 c9 [2] 6f c5 [2] 63 cf [2] 74 c4 [2] 6f 8a [2] 52 }

  condition:
    any of them
}