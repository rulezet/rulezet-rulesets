rule TTP_XOR_MULT_DOSStub_3472 {
  strings:
    $key_3472 = { 60 1a [2] 14 02 [2] 53 00 [2] 14 11 [2] 5a 1d [2] 56 17 [2] 41 1c [2] 5a 52 [2] 67 }

  condition:
    any of them
}