rule TTP_XOR_MULT_DOSStub_4c72 {
  strings:
    $key_4c72 = { 18 1a [2] 6c 02 [2] 2b 00 [2] 6c 11 [2] 22 1d [2] 2e 17 [2] 39 1c [2] 22 52 [2] 1f }

  condition:
    any of them
}