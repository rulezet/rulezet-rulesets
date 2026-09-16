rule TTP_XOR_MULT_DOSStub_4c58 {
  strings:
    $key_4c58 = { 18 30 [2] 6c 28 [2] 2b 2a [2] 6c 3b [2] 22 37 [2] 2e 3d [2] 39 36 [2] 22 78 [2] 1f }

  condition:
    any of them
}