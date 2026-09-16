rule TTP_XOR_MULT_DOSStub_4978 {
  strings:
    $key_4978 = { 1d 10 [2] 69 08 [2] 2e 0a [2] 69 1b [2] 27 17 [2] 2b 1d [2] 3c 16 [2] 27 58 [2] 1a }

  condition:
    any of them
}