rule TTP_XOR_MULT_DOSStub_0b0b {
  strings:
    $key_0b0b = { 5f 63 [2] 2b 7b [2] 6c 79 [2] 2b 68 [2] 65 64 [2] 69 6e [2] 7e 65 [2] 65 2b [2] 58 }

  condition:
    any of them
}