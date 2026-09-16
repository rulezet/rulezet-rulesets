rule TTP_XOR_MULT_DOSStub_3caa {
  strings:
    $key_3caa = { 68 c2 [2] 1c da [2] 5b d8 [2] 1c c9 [2] 52 c5 [2] 5e cf [2] 49 c4 [2] 52 8a [2] 6f }

  condition:
    any of them
}