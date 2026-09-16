rule TTP_XOR_MULT_DOSStub_f4aa {
  strings:
    $key_f4aa = { a0 c2 [2] d4 da [2] 93 d8 [2] d4 c9 [2] 9a c5 [2] 96 cf [2] 81 c4 [2] 9a 8a [2] a7 }

  condition:
    any of them
}