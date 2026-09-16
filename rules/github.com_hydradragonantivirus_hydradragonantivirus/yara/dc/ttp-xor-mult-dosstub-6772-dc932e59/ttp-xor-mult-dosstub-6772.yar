rule TTP_XOR_MULT_DOSStub_6772 {
  strings:
    $key_6772 = { 33 1a [2] 47 02 [2] 00 00 [2] 47 11 [2] 09 1d [2] 05 17 [2] 12 1c [2] 09 52 [2] 34 }

  condition:
    any of them
}