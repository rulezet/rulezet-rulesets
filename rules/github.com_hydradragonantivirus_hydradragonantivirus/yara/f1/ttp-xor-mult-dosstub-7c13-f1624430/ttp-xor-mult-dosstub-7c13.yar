rule TTP_XOR_MULT_DOSStub_7c13 {
  strings:
    $key_7c13 = { 28 7b [2] 5c 63 [2] 1b 61 [2] 5c 70 [2] 12 7c [2] 1e 76 [2] 09 7d [2] 12 33 [2] 2f }

  condition:
    any of them
}