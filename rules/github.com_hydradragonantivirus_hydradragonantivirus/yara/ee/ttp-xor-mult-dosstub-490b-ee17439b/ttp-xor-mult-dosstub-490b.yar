rule TTP_XOR_MULT_DOSStub_490b {
  strings:
    $key_490b = { 1d 63 [2] 69 7b [2] 2e 79 [2] 69 68 [2] 27 64 [2] 2b 6e [2] 3c 65 [2] 27 2b [2] 1a }

  condition:
    any of them
}