rule TTP_XOR_MULT_DOSStub_7078 {
  strings:
    $key_7078 = { 24 10 [2] 50 08 [2] 17 0a [2] 50 1b [2] 1e 17 [2] 12 1d [2] 05 16 [2] 1e 58 [2] 23 }

  condition:
    any of them
}