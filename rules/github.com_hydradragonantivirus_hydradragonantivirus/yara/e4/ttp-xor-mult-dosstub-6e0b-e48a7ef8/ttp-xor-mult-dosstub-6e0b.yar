rule TTP_XOR_MULT_DOSStub_6e0b {
  strings:
    $key_6e0b = { 3a 63 [2] 4e 7b [2] 09 79 [2] 4e 68 [2] 00 64 [2] 0c 6e [2] 1b 65 [2] 00 2b [2] 3d }

  condition:
    any of them
}