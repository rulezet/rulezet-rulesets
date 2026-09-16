rule TTP_XOR_MULT_DOSStub_b1aa {
  strings:
    $key_b1aa = { e5 c2 [2] 91 da [2] d6 d8 [2] 91 c9 [2] df c5 [2] d3 cf [2] c4 c4 [2] df 8a [2] e2 }

  condition:
    any of them
}