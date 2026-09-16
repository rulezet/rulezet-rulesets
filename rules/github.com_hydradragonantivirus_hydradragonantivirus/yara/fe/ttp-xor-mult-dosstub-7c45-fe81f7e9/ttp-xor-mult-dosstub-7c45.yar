rule TTP_XOR_MULT_DOSStub_7c45 {
  strings:
    $key_7c45 = { 28 2d [2] 5c 35 [2] 1b 37 [2] 5c 26 [2] 12 2a [2] 1e 20 [2] 09 2b [2] 12 65 [2] 2f }

  condition:
    any of them
}