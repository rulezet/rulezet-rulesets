rule TTP_XOR_MULT_DOSStub_34aa {
  strings:
    $key_34aa = { 60 c2 [2] 14 da [2] 53 d8 [2] 14 c9 [2] 5a c5 [2] 56 cf [2] 41 c4 [2] 5a 8a [2] 67 }

  condition:
    any of them
}