rule TTP_XOR_MULT_DOSStub_4f0b {
  strings:
    $key_4f0b = { 1b 63 [2] 6f 7b [2] 28 79 [2] 6f 68 [2] 21 64 [2] 2d 6e [2] 3a 65 [2] 21 2b [2] 1c }

  condition:
    any of them
}