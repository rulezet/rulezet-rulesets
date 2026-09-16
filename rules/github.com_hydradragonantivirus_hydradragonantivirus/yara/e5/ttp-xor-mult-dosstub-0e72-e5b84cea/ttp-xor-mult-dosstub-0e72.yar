rule TTP_XOR_MULT_DOSStub_0e72 {
  strings:
    $key_0e72 = { 5a 1a [2] 2e 02 [2] 69 00 [2] 2e 11 [2] 60 1d [2] 6c 17 [2] 7b 1c [2] 60 52 [2] 5d }

  condition:
    any of them
}