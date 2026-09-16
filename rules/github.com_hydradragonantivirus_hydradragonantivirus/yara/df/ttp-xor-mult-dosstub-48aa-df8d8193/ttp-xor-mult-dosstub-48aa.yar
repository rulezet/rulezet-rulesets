rule TTP_XOR_MULT_DOSStub_48aa {
  strings:
    $key_48aa = { 1c c2 [2] 68 da [2] 2f d8 [2] 68 c9 [2] 26 c5 [2] 2a cf [2] 3d c4 [2] 26 8a [2] 1b }

  condition:
    any of them
}