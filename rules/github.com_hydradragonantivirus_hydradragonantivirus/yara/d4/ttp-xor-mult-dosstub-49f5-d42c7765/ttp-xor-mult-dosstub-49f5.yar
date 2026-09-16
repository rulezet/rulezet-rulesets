rule TTP_XOR_MULT_DOSStub_49f5 {
  strings:
    $key_49f5 = { 1d 9d [2] 69 85 [2] 2e 87 [2] 69 96 [2] 27 9a [2] 2b 90 [2] 3c 9b [2] 27 d5 [2] 1a }

  condition:
    any of them
}