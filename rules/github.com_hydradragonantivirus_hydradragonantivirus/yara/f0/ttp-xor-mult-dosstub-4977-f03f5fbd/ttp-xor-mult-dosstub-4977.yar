rule TTP_XOR_MULT_DOSStub_4977 {
  strings:
    $key_4977 = { 1d 1f [2] 69 07 [2] 2e 05 [2] 69 14 [2] 27 18 [2] 2b 12 [2] 3c 19 [2] 27 57 [2] 1a }

  condition:
    any of them
}