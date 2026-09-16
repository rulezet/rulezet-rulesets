rule TTP_XOR_MULT_DOSStub_7c01 {
  strings:
    $key_7c01 = { 28 69 [2] 5c 71 [2] 1b 73 [2] 5c 62 [2] 12 6e [2] 1e 64 [2] 09 6f [2] 12 21 [2] 2f }

  condition:
    any of them
}