rule TTP_XOR_MULT_DOSStub_49e0 {
  strings:
    $key_49e0 = { 1d 88 [2] 69 90 [2] 2e 92 [2] 69 83 [2] 27 8f [2] 2b 85 [2] 3c 8e [2] 27 c0 [2] 1a }

  condition:
    any of them
}