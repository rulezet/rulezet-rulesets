rule TTP_XOR_MULT_DOSStub_4d0b {
  strings:
    $key_4d0b = { 19 63 [2] 6d 7b [2] 2a 79 [2] 6d 68 [2] 23 64 [2] 2f 6e [2] 38 65 [2] 23 2b [2] 1e }

  condition:
    any of them
}