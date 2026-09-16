rule TTP_XOR_MULT_DOSStub_16aa {
  strings:
    $key_16aa = { 42 c2 [2] 36 da [2] 71 d8 [2] 36 c9 [2] 78 c5 [2] 74 cf [2] 63 c4 [2] 78 8a [2] 45 }

  condition:
    any of them
}