rule TTP_XOR_MULT_DOSStub_4903 {
  strings:
    $key_4903 = { 1d 6b [2] 69 73 [2] 2e 71 [2] 69 60 [2] 27 6c [2] 2b 66 [2] 3c 6d [2] 27 23 [2] 1a }

  condition:
    any of them
}