rule TTP_XOR_MULT_DOSStub_7a68 {
  strings:
    $key_7a68 = { 2e 00 [2] 5a 18 [2] 1d 1a [2] 5a 0b [2] 14 07 [2] 18 0d [2] 0f 06 [2] 14 48 [2] 29 }

  condition:
    any of them
}