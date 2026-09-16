rule TTP_XOR_MULT_DOSStub_61aa {
  strings:
    $key_61aa = { 35 c2 [2] 41 da [2] 06 d8 [2] 41 c9 [2] 0f c5 [2] 03 cf [2] 14 c4 [2] 0f 8a [2] 32 }

  condition:
    any of them
}