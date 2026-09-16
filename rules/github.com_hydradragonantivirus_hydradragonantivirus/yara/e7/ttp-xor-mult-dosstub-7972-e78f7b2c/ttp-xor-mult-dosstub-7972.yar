rule TTP_XOR_MULT_DOSStub_7972 {
  strings:
    $key_7972 = { 2d 1a [2] 59 02 [2] 1e 00 [2] 59 11 [2] 17 1d [2] 1b 17 [2] 0c 1c [2] 17 52 [2] 2a }

  condition:
    any of them
}