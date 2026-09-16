rule TTP_XOR_MULT_DOSStub_11aa {
  strings:
    $key_11aa = { 45 c2 [2] 31 da [2] 76 d8 [2] 31 c9 [2] 7f c5 [2] 73 cf [2] 64 c4 [2] 7f 8a [2] 42 }

  condition:
    any of them
}