rule TTP_XOR_MULT_DOSStub_0772 {
  strings:
    $key_0772 = { 53 1a [2] 27 02 [2] 60 00 [2] 27 11 [2] 69 1d [2] 65 17 [2] 72 1c [2] 69 52 [2] 54 }

  condition:
    any of them
}