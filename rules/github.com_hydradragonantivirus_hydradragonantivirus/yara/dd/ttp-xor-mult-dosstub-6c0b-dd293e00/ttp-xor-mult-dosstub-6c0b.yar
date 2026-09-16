rule TTP_XOR_MULT_DOSStub_6c0b {
  strings:
    $key_6c0b = { 38 63 [2] 4c 7b [2] 0b 79 [2] 4c 68 [2] 02 64 [2] 0e 6e [2] 19 65 [2] 02 2b [2] 3f }

  condition:
    any of them
}