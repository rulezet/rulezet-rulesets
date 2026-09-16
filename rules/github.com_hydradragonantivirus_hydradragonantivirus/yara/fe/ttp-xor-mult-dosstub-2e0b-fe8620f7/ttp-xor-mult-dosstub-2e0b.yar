rule TTP_XOR_MULT_DOSStub_2e0b {
  strings:
    $key_2e0b = { 7a 63 [2] 0e 7b [2] 49 79 [2] 0e 68 [2] 40 64 [2] 4c 6e [2] 5b 65 [2] 40 2b [2] 7d }

  condition:
    any of them
}