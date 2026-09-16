rule TTP_XOR_MULT_DOSStub_4913 {
  strings:
    $key_4913 = { 1d 7b [2] 69 63 [2] 2e 61 [2] 69 70 [2] 27 7c [2] 2b 76 [2] 3c 7d [2] 27 33 [2] 1a }

  condition:
    any of them
}