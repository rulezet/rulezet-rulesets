rule TTP_XOR_MULT_DOSStub_2d0b {
  strings:
    $key_2d0b = { 79 63 [2] 0d 7b [2] 4a 79 [2] 0d 68 [2] 43 64 [2] 4f 6e [2] 58 65 [2] 43 2b [2] 7e }

  condition:
    any of them
}