rule TTP_XOR_MULT_DOSStub_6b72 {
  strings:
    $key_6b72 = { 3f 1a [2] 4b 02 [2] 0c 00 [2] 4b 11 [2] 05 1d [2] 09 17 [2] 1e 1c [2] 05 52 [2] 38 }

  condition:
    any of them
}