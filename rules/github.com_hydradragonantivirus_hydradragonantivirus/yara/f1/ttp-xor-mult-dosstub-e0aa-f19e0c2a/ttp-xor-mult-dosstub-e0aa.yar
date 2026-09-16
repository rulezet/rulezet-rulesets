rule TTP_XOR_MULT_DOSStub_e0aa {
  strings:
    $key_e0aa = { b4 c2 [2] c0 da [2] 87 d8 [2] c0 c9 [2] 8e c5 [2] 82 cf [2] 95 c4 [2] 8e 8a [2] b3 }

  condition:
    any of them
}