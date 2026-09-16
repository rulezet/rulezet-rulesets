rule TTP_XOR_MULT_DOSStub_7d72 {
  strings:
    $key_7d72 = { 29 1a [2] 5d 02 [2] 1a 00 [2] 5d 11 [2] 13 1d [2] 1f 17 [2] 08 1c [2] 13 52 [2] 2e }

  condition:
    any of them
}