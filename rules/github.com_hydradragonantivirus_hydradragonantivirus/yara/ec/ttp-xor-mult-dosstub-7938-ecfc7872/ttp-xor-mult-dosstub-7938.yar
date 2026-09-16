rule TTP_XOR_MULT_DOSStub_7938 {
  strings:
    $key_7938 = { 2d 50 [2] 59 48 [2] 1e 4a [2] 59 5b [2] 17 57 [2] 1b 5d [2] 0c 56 [2] 17 18 [2] 2a }

  condition:
    any of them
}