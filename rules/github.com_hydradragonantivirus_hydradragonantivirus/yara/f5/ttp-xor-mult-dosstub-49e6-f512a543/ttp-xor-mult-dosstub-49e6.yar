rule TTP_XOR_MULT_DOSStub_49e6 {
  strings:
    $key_49e6 = { 1d 8e [2] 69 96 [2] 2e 94 [2] 69 85 [2] 27 89 [2] 2b 83 [2] 3c 88 [2] 27 c6 [2] 1a }

  condition:
    any of them
}