rule TTP_XOR_MULT_DOSStub_3772 {
  strings:
    $key_3772 = { 63 1a [2] 17 02 [2] 50 00 [2] 17 11 [2] 59 1d [2] 55 17 [2] 42 1c [2] 59 52 [2] 64 }

  condition:
    any of them
}