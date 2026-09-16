rule TTP_XOR_MULT_DOSStub_7b0b {
  strings:
    $key_7b0b = { 2f 63 [2] 5b 7b [2] 1c 79 [2] 5b 68 [2] 15 64 [2] 19 6e [2] 0e 65 [2] 15 2b [2] 28 }

  condition:
    any of them
}