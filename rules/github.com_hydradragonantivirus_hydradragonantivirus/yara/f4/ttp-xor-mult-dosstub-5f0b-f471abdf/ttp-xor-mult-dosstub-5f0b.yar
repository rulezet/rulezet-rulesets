rule TTP_XOR_MULT_DOSStub_5f0b {
  strings:
    $key_5f0b = { 0b 63 [2] 7f 7b [2] 38 79 [2] 7f 68 [2] 31 64 [2] 3d 6e [2] 2a 65 [2] 31 2b [2] 0c }

  condition:
    any of them
}