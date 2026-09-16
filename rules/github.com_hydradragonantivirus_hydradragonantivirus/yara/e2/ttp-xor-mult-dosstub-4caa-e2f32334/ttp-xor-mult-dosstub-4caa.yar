rule TTP_XOR_MULT_DOSStub_4caa {
  strings:
    $key_4caa = { 18 c2 [2] 6c da [2] 2b d8 [2] 6c c9 [2] 22 c5 [2] 2e cf [2] 39 c4 [2] 22 8a [2] 1f }

  condition:
    any of them
}