rule TTP_XOR_MULT_DOSStub_05aa {
  strings:
    $key_05aa = { 51 c2 [2] 25 da [2] 62 d8 [2] 25 c9 [2] 6b c5 [2] 67 cf [2] 70 c4 [2] 6b 8a [2] 56 }

  condition:
    any of them
}