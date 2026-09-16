rule TTP_XOR_MULT_DOSStub_4b0b {
  strings:
    $key_4b0b = { 1f 63 [2] 6b 7b [2] 2c 79 [2] 6b 68 [2] 25 64 [2] 29 6e [2] 3e 65 [2] 25 2b [2] 18 }

  condition:
    any of them
}