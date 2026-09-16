rule TTP_XOR_MULT_DOSStub_b6aa {
  strings:
    $key_b6aa = { e2 c2 [2] 96 da [2] d1 d8 [2] 96 c9 [2] d8 c5 [2] d4 cf [2] c3 c4 [2] d8 8a [2] e5 }

  condition:
    any of them
}