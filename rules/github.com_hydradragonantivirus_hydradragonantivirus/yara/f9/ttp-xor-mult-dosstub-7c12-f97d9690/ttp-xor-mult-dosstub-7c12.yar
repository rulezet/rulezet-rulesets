rule TTP_XOR_MULT_DOSStub_7c12 {
  strings:
    $key_7c12 = { 28 7a [2] 5c 62 [2] 1b 60 [2] 5c 71 [2] 12 7d [2] 1e 77 [2] 09 7c [2] 12 32 [2] 2f }

  condition:
    any of them
}