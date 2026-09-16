rule TTP_XOR_MULT_DOSStub_7c0b {
  strings:
    $key_7c0b = { 28 63 [2] 5c 7b [2] 1b 79 [2] 5c 68 [2] 12 64 [2] 1e 6e [2] 09 65 [2] 12 2b [2] 2f }

  condition:
    any of them
}