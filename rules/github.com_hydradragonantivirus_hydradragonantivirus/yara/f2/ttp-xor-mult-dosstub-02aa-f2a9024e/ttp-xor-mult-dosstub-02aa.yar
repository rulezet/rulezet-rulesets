rule TTP_XOR_MULT_DOSStub_02aa {
  strings:
    $key_02aa = { 56 c2 [2] 22 da [2] 65 d8 [2] 22 c9 [2] 6c c5 [2] 60 cf [2] 77 c4 [2] 6c 8a [2] 51 }

  condition:
    any of them
}