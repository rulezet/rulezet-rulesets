rule TTP_XOR_MULT_DOSStub_7c15 {
  strings:
    $key_7c15 = { 28 7d [2] 5c 65 [2] 1b 67 [2] 5c 76 [2] 12 7a [2] 1e 70 [2] 09 7b [2] 12 35 [2] 2f }

  condition:
    any of them
}