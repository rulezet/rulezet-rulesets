rule TTP_XOR_MULT_DOSStub_49e4 {
  strings:
    $key_49e4 = { 1d 8c [2] 69 94 [2] 2e 96 [2] 69 87 [2] 27 8b [2] 2b 81 [2] 3c 8a [2] 27 c4 [2] 1a }

  condition:
    any of them
}