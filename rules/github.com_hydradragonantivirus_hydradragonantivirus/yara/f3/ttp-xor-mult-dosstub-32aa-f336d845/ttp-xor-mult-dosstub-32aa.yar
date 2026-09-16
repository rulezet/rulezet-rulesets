rule TTP_XOR_MULT_DOSStub_32aa {
  strings:
    $key_32aa = { 66 c2 [2] 12 da [2] 55 d8 [2] 12 c9 [2] 5c c5 [2] 50 cf [2] 47 c4 [2] 5c 8a [2] 61 }

  condition:
    any of them
}