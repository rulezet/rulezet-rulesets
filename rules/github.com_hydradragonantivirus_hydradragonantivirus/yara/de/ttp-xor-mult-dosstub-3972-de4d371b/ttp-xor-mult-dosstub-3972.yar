rule TTP_XOR_MULT_DOSStub_3972 {
  strings:
    $key_3972 = { 6d 1a [2] 19 02 [2] 5e 00 [2] 19 11 [2] 57 1d [2] 5b 17 [2] 4c 1c [2] 57 52 [2] 6a }

  condition:
    any of them
}