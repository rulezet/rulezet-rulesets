rule TTP_XOR_MULT_DOSStub_4932 {
  strings:
    $key_4932 = { 1d 5a [2] 69 42 [2] 2e 40 [2] 69 51 [2] 27 5d [2] 2b 57 [2] 3c 5c [2] 27 12 [2] 1a }

  condition:
    any of them
}