rule TTP_XOR_MULT_DOSStub_3b0b {
  strings:
    $key_3b0b = { 6f 63 [2] 1b 7b [2] 5c 79 [2] 1b 68 [2] 55 64 [2] 59 6e [2] 4e 65 [2] 55 2b [2] 68 }

  condition:
    any of them
}