rule TTP_XOR_MULT_DOSStub_7c59 {
  strings:
    $key_7c59 = { 28 31 [2] 5c 29 [2] 1b 2b [2] 5c 3a [2] 12 36 [2] 1e 3c [2] 09 37 [2] 12 79 [2] 2f }

  condition:
    any of them
}