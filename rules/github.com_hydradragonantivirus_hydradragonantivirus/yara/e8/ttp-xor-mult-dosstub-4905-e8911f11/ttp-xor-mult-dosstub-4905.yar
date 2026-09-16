rule TTP_XOR_MULT_DOSStub_4905 {
  strings:
    $key_4905 = { 1d 6d [2] 69 75 [2] 2e 77 [2] 69 66 [2] 27 6a [2] 2b 60 [2] 3c 6b [2] 27 25 [2] 1a }

  condition:
    any of them
}