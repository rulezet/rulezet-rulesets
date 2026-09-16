rule TTP_XOR_MULT_DOSStub_4918 {
  strings:
    $key_4918 = { 1d 70 [2] 69 68 [2] 2e 6a [2] 69 7b [2] 27 77 [2] 2b 7d [2] 3c 76 [2] 27 38 [2] 1a }

  condition:
    any of them
}