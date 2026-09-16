rule TTP_XOR_MULT_DOSStub_5e72 {
  strings:
    $key_5e72 = { 0a 1a [2] 7e 02 [2] 39 00 [2] 7e 11 [2] 30 1d [2] 3c 17 [2] 2b 1c [2] 30 52 [2] 0d }

  condition:
    any of them
}